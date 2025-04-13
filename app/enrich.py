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

    for cve_id, details in cves.items():
        key = f"{cve_id}:{details.get('summary', '')}"
        if key in seen_ids:
            continue
        seen_ids.add(key)

        description = details.get("summary", "").lower()
        severity = details.get("cvss", 0)
        entry = {
            "id": cve_id,
            "title": details.get("summary", "")[:100],
            "description": details.get("summary", ""),
            "cvss": details.get("cvss"),
            "exploit": any(src in ' '.join(details.get("references", [])) for src in ["exploit", "packetstorm", "metasploit"]),
            "references": details.get("references", [])
        }

        if severity and severity >= 9:
            grouped["Critical"].append(entry)
        elif severity and severity >= 7:
            grouped["High Severity"].append(entry)
        elif "null pointer" in description or "improper" in description:
            grouped["Known Patterns"].append(entry)
        elif any(v in entry["title"].lower() for v in ["suse", "rhsa", "openvas"]):
            grouped["Vendor Advisories"].append(entry)
        else:
            grouped["Other"].append(entry)

    return grouped


def analyze_host(host):
    ip = host.get("ip_str")
    org = host.get("org", "Unknown")
    country = host.get("country_name", "Unknown")
    city = host.get("city", "Unknown")
    isp = host.get("isp", "Unknown")
    hostnames = host.get("hostnames", [])
    domains = host.get("domains", [])
    os = host.get("os", "Unknown")
    ports = host.get("ports", [])
    tags = host.get("tags", [])
    last_seen = host.get("last_update", "")
    flagged_ports = [p for p in ports if p in [21, 22, 23, 3389]]
    print("[DEBUG] Raw top-level vulns field from Shodan:", flush=True)
    print(json.dumps(host.get("vulns", {}), indent=2), flush=True)

    merged_services = {}
    seen_keys = set()

    for item in host.get("data", []):
        product = item.get("product")
        version = item.get("version", "")
        port = item.get("port")
        cves = item.get("vulns", {})

        if not product or not cves:
            continue

        key = f"{product}:{version}:{port}"
        if key in seen_keys:
            continue
        seen_keys.add(key)

        grouped_cves = categorize_cves(cves)

        merged_services[key] = {
            "product": product,
            "version": version,
            "ports": [port],
            "grouped_cves": grouped_cves
        }

    services = list(merged_services.values())

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
        "last_seen": last_seen,
        "services": services
    }
