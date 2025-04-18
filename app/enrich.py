import json
from app.nvd_lookup import get_cve_details_from_nvd
import time

def categorize_cves(cves):
    grouped = {
        "Critical": [],
        "High Severity": [],
        "Known Patterns": [],
        "Vendor Advisories": [],
        "Other": []
    }

    seen_ids = set()

    for cve in cves:
        cve_id = cve.get("id") or cve.get("_source", {}).get("id", "Unknown")
        title = cve.get("title") or cve.get("_source", {}).get("title", "")
        description = (
            cve.get("description") or
            cve.get("flatDescription") or
            cve.get("_source", {}).get("description") or
            cve.get("_source", {}).get("flatDescription") or
            ""
        ).lower()
        severity = (
            cve.get("cvss", {}).get("severity") or
            cve.get("_source", {}).get("cvss", {}).get("severity", "")
        ).upper()

        key = f"{cve_id}:{title}"
        if key in seen_ids:
            continue
        seen_ids.add(key)
    
        entry = {
            "id": cve_id,
            "title": title,
            "description": description or "No description",
            "cvss": cve.get("cvss", {}).get("score") or cve.get("_source", {}).get("cvss", {}).get("score"),
            "exploit": "exploitdb" in json.dumps(cve).lower(),
            "references": cve.get("references") or cve.get("_source", {}).get("references", [])
        }


        if severity == "CRITICAL":
            grouped["Critical"].append(entry)
        elif severity == "HIGH":
            grouped["High Severity"].append(entry)
        elif "null pointer" in description or "improper" in description:
            grouped["Known Patterns"].append(entry)
        elif any(v in title.lower() for v in ["suse", "rhsa", "openvas"]):
            grouped["Vendor Advisories"].append(entry)
        else:
            grouped["Other"].append(entry)

    return grouped


def analyze_host(host):
    from collections import defaultdict

    ip = host.get("ip_str")
    org = host.get("org", "Unknown")
    country = host.get("country_name", "Unknown")
    city = host.get("city", "Unknown")
    isp = host.get("isp", "Unknown")
    asn = host.get("asn", "Unknown")
    hostnames = host.get("hostnames", [])
    domains = host.get("domains", [])
    os = host.get("os", "Unknown")
    ports = host.get("ports", [])
    tags = host.get("tags", [])
    last_seen = host.get("last_update", "")
    flagged_ports = [p for p in ports if p in [21, 22, 23, 3389]]

    merged_services = {}
    seen_services = set()

    for item in host.get("data", []):
        product = item.get("product")
        version = item.get("version")
        port = item.get("port")

        if not product or not version:
            continue

        key = f"{product}:{version}:{port}"
        if key in seen_services:
            continue
        seen_services.add(key)

        # Pull per-service CVEs directly from item-level "vulns"
        grouped_cves = {
            "Other": [{"id": v, "title": "", "description": ""} for v in item.get("vulns", {}).keys()]
        }

        merge_key = f"{product}::{version}"
        cve_signature = tuple(sorted(cve["id"] for group in grouped_cves.values() for cve in group))

        if merge_key in merged_services:
            if merged_services[merge_key]["cve_signature"] == cve_signature:
                merged_services[merge_key]["ports"].add(port)
                continue
            else:
                merge_key += f":{port}"

        merged_services[merge_key] = {
            "product": product,
            "version": version,
            "ports": {port},
            "grouped_cves": grouped_cves,
            "cve_signature": cve_signature
        }

    services = []
    for entry in merged_services.values():
        services.append({
            "product": entry["product"],
            "version": entry["version"],
            "ports": sorted(entry["ports"]),
            "grouped_cves": entry["grouped_cves"]
        })

    # 🔎 Global CVEs: extract unique IDs from ALL port-level "vulns"
    vuln_ids = set()
    for item in host.get("data", []):
        if isinstance(item.get("vulns"), dict):
            vuln_ids.update(item["vulns"].keys())
    vuln_ids = list(vuln_ids)

    # 🌐 Enrich + group
    raw_global_entries = []
    for v in vuln_ids:
        details = get_cve_details_from_nvd(v)
        if not details:
            details = {"id": v, "title": "", "description": "", "cvss": None, "severity": "UNKNOWN"}
        raw_global_entries.append(details)
        time.sleep(1)  # prevent NVD rate-limiting (if no API key)

    grouped_global_cves = categorize_cves(raw_global_entries)

    return {
        "ip": ip,
        "org": org,
        "hostnames": hostnames,
        "domains": domains,
        "isp": isp,
        "country": country,
        "city": city,
        "os": os,
        "ports": ports,
        "flagged_ports": flagged_ports,
        "tags": tags,
        "cves": vuln_ids,
        "last_seen": last_seen,
        "services": services,
        "global_cves": grouped_global_cves,
    }
