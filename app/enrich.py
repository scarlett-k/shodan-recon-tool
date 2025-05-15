from app.vuln_lookup import search_cves
import requests
import time
import json

# Optional simple cache to avoid hammering the API during tests (in-memory)
cve_cache = {}

def enrich_cve(cve_id):
    if cve_id in cve_cache:
        return cve_cache[cve_id]  # Return from cache if already fetched

    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"[WARNING] NVD API failed for {cve_id}: {response.status_code}")
            return None

        data = response.json()

        cve_item = data.get("result", {}).get("CVE_Items", [])[0]
        description = cve_item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "No description")
        
        # Prefer CVSS v3 if available, fallback to v2
        impact = cve_item.get("impact", {})
        if "baseMetricV3" in impact:
            cvss_score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
            severity = impact["baseMetricV3"]["cvssV3"]["baseSeverity"]
        elif "baseMetricV2" in impact:
            cvss_score = impact["baseMetricV2"]["cvssV2"]["baseScore"]
            severity = "HIGH" if cvss_score >= 7 else "MEDIUM" if cvss_score >= 4 else "LOW"
        else:
            cvss_score = None
            severity = "UNKNOWN"

        enriched = {
            "id": cve_id,
            "description": description,
            "cvss": cvss_score,
            "severity": severity
        }

        cve_cache[cve_id] = enriched  # Save to cache

        # Optional: Sleep to respect NVD rate limit (5 req/sec without key)
        time.sleep(0.25)

        return enriched

    except Exception as e:
        print(f"[ERROR] Failed to enrich CVE {cve_id}: {e}")
        return None

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
