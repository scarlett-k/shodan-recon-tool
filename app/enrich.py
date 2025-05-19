import requests
import time

# Optional simple cache
cve_cache = {}

def enrich_cve(cve_id, shodan_vuln_data=None):
    if cve_id in cve_cache:
        return cve_cache[cve_id]

    # ✅ Use Shodan CVE data if provided
    if shodan_vuln_data:
        description = shodan_vuln_data.get("summary", "No description")
        cvss_score = shodan_vuln_data.get("cvss")

        # Derive severity from CVSS score
        if isinstance(cvss_score, (float, int)):
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"
            else:
                severity = "UNKNOWN"
        else:
            severity = "UNKNOWN"

        enriched = {
            "id": cve_id,
            "description": description,
            "cvss": cvss_score,
            "severity": severity
        }

        cve_cache[cve_id] = enriched
        print(f"[INFO] Enriched {cve_id} (Shodan): {severity} | {description[:60]}...")
        return enriched

    # 🔄 Fallback to MITRE if no Shodan data
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            print(f"[WARNING] MITRE API 404 for {cve_id}: Not found")
            return None
        elif response.status_code != 200:
            print(f"[WARNING] MITRE API failed for {cve_id}: {response.status_code}")
            return None

        data = response.json()
        cve_data = data.get("containers", {}).get("cna", {})

        description = "No description"
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        # MITRE usually doesn’t have CVSS in CNA
        cvss_score = None
        severity = "UNKNOWN"

        enriched = {
            "id": cve_id,
            "description": description,
            "cvss": cvss_score,
            "severity": severity
        }

        cve_cache[cve_id] = enriched
        print(f"[INFO] Enriched {cve_id} (MITRE): {severity} | {description[:60]}...")
        time.sleep(1)
        return enriched

    except Exception as e:
        print(f"[ERROR] Failed to enrich CVE {cve_id}: {e}")
        return None


def categorize_cves(cve_ids, shodan_vuln_data={}):
    grouped = {
        "Critical": [],
        "High Severity": [],
        "Known Patterns": [],
        "Vendor Advisories": [],
        "Other": []
    }

    seen_ids = set()
    for cve_id in cve_ids:
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)

        vuln_data = shodan_vuln_data.get(cve_id)
        enriched = enrich_cve(cve_id, vuln_data)
        if not enriched:
            entry = {
                "id": cve_id,
                "title": "",
                "description": "No description",
                "cvss": None,
                "exploit": False,
                "references": []
            }
            grouped["Other"].append(entry)
            continue

        entry = {
            "id": cve_id,
            "title": "",
            "description": enriched["description"],
            "cvss": enriched["cvss"],
            "exploit": False,
            "references": []
        }

        severity = enriched["severity"].upper()
        if severity == "CRITICAL":
            grouped["Critical"].append(entry)
        elif severity == "HIGH":
            grouped["High Severity"].append(entry)
        elif "null pointer" in enriched["description"].lower() or "improper" in enriched["description"].lower():
            grouped["Known Patterns"].append(entry)
        elif any(v in enriched["description"].lower() for v in ["suse", "rhsa", "openvas"]):
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

    # ✅ Categorize top-level host-level CVEs
    raw_top_vulns = host.get("vulns", [])
    grouped_top_level_cves = categorize_cves(raw_top_vulns)
    print(f"[DEBUG] Top-level host vulns: {raw_top_vulns}")

    for i, item in enumerate(host.get("data", [])):
        product = item.get("product")
        version = item.get("version")
        port = item.get("port")

        if not product or not version:
            continue

        key = f"{product}:{version}:{port}"
        if key in seen_services:
            continue
        seen_services.add(key)

        raw_cves = item.get("vulns")

        # ✅ Fallback: if this is the first service and no CVEs are found, use top-level
        if not raw_cves and i == 0:
            raw_cves = host.get("vulns", [])
            print(f"[DEBUG] Using top-level CVEs as fallback for service on port {port}: {raw_cves}")

        # ✅ Final fallback if still nothing
        if not raw_cves:
            raw_cves = host.get("opts", {}).get("vulns", [])
            print(f"[DEBUG] fallback host opts vulns for {host.get('ip_str')}: {raw_cves}")

        # Normalize CVE format
        if isinstance(raw_cves, dict):
            cves = list(raw_cves.keys())
        elif isinstance(raw_cves, list):
            cves = raw_cves
        else:
            cves = []

        grouped_cves = categorize_cves(cves)

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
        "cves": grouped_top_level_cves,
        "grouped_top_level_cves": grouped_top_level_cves,
        "last_seen": last_seen,
        "services": services
    }
