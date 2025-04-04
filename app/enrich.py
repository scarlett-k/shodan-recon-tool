from app.vuln_lookup import search_cves

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
        print("PRINTING KEY!!!!!!!!!!!!!!!!!!!!!")
        print(key)

        entry = {
            "id": cve_id,
            "title": title,
            "description": description or "No description"
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

    vulns = host.get("vulns")
    ip = host.get("ip_str")
    org = host.get("org", "Unknown")
    country = host.get("location", {}).get("country_name", "Unknown")
    ports = host.get("ports", [])
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

        cves = search_cves(product, version)
        grouped_cves = categorize_cves(cves)

        merge_key = f"{product}::{version}"
        cve_signature = tuple(sorted((cve["id"] for group in grouped_cves.values() for cve in group)))

        if merge_key in merged_services:
            if merged_services[merge_key]["cve_signature"] == cve_signature:
                merged_services[merge_key]["ports"].add(port)
                continue  # Just add the port to existing service
            else:
                # Create a new key if CVEs differ
                merge_key += f":{port}"

        merged_services[merge_key] = {
            "product": product,
            "version": version,
            "ports": {port},
            "grouped_cves": grouped_cves,
            "cve_signature": cve_signature  # Only used for comparison, not returned
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
        "country": country,
        "ports": ports,
        "flagged_ports": flagged_ports,
        "cves": vulns if isinstance(vulns, list) else list(vulns.keys()) if isinstance(vulns, dict) else [],
        "last_seen": last_seen,
        "services": services
    }
