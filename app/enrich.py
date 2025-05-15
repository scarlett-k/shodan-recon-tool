from app.vuln_lookup import search_cves
import json

import json

import json

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
        cve_id = cve.get("id", "Unknown")

        # With only ID, we can't determine severity from Shodan alone
        entry = {
            "id": cve_id,
            "title": "",
            "description": "No description",
            "cvss": None,
            "exploit": False,
            "references": []
        }

        key = cve_id
        if key in seen_ids:
            continue
        seen_ids.add(key)

        grouped["Other"].append(entry)  # Default to Other as Shodan CVEs have no severity info

    return grouped

def analyze_host(host):
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

        raw_cves = item.get("vulns", [])
        if isinstance(raw_cves, dict):
            cves = list(raw_cves.keys())
        elif isinstance(raw_cves, list):
            cves = raw_cves
        else:
            cves = []

        grouped_cves = categorize_cves([{"id": cve_id} for cve_id in cves])

        merge_key = f"{product}::{version}"
        cve_signature = tuple(sorted((cve["id"] for group in grouped_cves.values() for cve in group)))

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
        "cves": host.get("opts", {}).get("vulns", []),
        "last_seen": last_seen,
        "services": services
    }
