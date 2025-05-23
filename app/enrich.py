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


def flatten_cves(cve_ids, shodan_vuln_data={}):
    seen_ids = set()
    flat_list = []

    for cve_id in cve_ids:
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)

        vuln_data = shodan_vuln_data.get(cve_id)
        enriched = enrich_cve(cve_id, vuln_data)
        if not enriched:
            flat_list.append({
                "id": cve_id,
                "title": "",
                "description": "No description",
                "cvss": None,
                "exploit": False,
                "references": []
            })
            continue

        flat_list.append({
            "id": cve_id,
            "title": "",
            "description": enriched["description"],
            "cvss": enriched["cvss"],
            "severity": enriched["severity"],
            "exploit": False,
            "references": []
        })

    return flat_list
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

    services = []
    seen_services = set()

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

        if not raw_cves and i == 0:
            raw_cves = host.get("vulns", [])
            print(f"[DEBUG] Using top-level CVEs as fallback for service on port {port}: {raw_cves}")

        if not raw_cves:
            raw_cves = host.get("opts", {}).get("vulns", [])

        if isinstance(raw_cves, dict):
            cves = list(raw_cves.keys())
        elif isinstance(raw_cves, list):
            cves = raw_cves
        else:
            cves = []

        flat_cves = flatten_cves(cves)

        services.append({
            "product": product,
            "version": version,
            "ports": [port],
            "vulnerabilities": flat_cves
        })

    # Handle top-level CVEs as well
    top_level_vulns = flatten_cves(host.get("vulns", []))

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
        "top_vulnerabilities": top_level_vulns,
        "last_seen": last_seen,
        "services": services
    }
