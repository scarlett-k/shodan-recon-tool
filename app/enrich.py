from app.vuln_lookup import search_cves
import requests
import time
import json
import os

# Pull API key safely from env vars (default to empty string if not set)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

def categorize_cves(cve_ids):
    grouped = {
        "Critical": [],
        "High Severity": [],
        "Known Patterns": [],
        "Vendor Advisories": [],
        "Other": []
    }
  
    seen_ids = set()
    for cve_id in cve_ids:  # no need to check dict form anymore
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)


        # 🔥 Call your NVD enrichment function
        enriched = enrich_cve(cve_id)
        if not enriched:
            # Fallback if enrichment failed
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

        # Build enriched entry
        entry = {
            "id": cve_id,
            "title": "",
            "description": enriched["description"],
            "cvss": enriched["cvss"],
            "exploit": False,
            "references": []
        }

        # ✅ Categorize by NVD severity
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


# Optional simple cache
cve_cache = {}

def enrich_cve(cve_id):

    if not NVD_API_KEY:
        print("[ERROR] NVD_API_KEY is not set in the environment variables.")
        return None

    url = f"https://services.nvd.nist.gov/rest/json/cve/2.0/{cve_id}"
    headers = {
        "apiKey": NVD_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            print(f"[WARNING] NVD API 404 for {cve_id}: Not found")
            return None
        elif response.status_code == 403:
            print(f"[ERROR] NVD API 403 for {cve_id}: Forbidden (check API key or rate limits)")
            return None
        elif response.status_code != 200:
            print(f"[WARNING] NVD API failed for {cve_id}: {response.status_code}")
            return None

        data = response.json()
        cve_list = data.get("vulnerabilities", [])

        if not cve_list:
            print(f"[WARNING] NVD API returned no data for {cve_id}")
            return None

        cve_data = cve_list[0]["cve"]

        # ✅ Description
        description = next(
            (desc["value"] for desc in cve_data.get("descriptions", []) if desc.get("lang") == "en"),
            "No description"
        )

        # ✅ CVSS metrics
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data["baseScore"]
            severity = cvss_data["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss_data["baseScore"]
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "MEDIUM")
        else:
            cvss_score = None
            severity = "UNKNOWN"

        enriched = {
            "id": cve_id,
            "description": description,
            "cvss": cvss_score,
            "severity": severity
        }

        cve_cache[cve_id] = enriched
        print(f"[INFO] Enriched {cve_id}: {severity} | {description[:60]}...")
        time.sleep(1)  # Respect rate limit
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
    print(f"[DEBUG] Top-level host vulns: {host.get('vulns')}")
    print(f"[DEBUG] host['data'][i]['vulns']: {item.get('vulns')}")
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

        raw_cves = item.get("vulns")
        print(f"[DEBUG] item vulns for {item.get('ip_str')}: {raw_cves}")

        if not raw_cves:
            raw_cves = host.get("opts", {}).get("vulns", [])
            print(f"[DEBUG] fallback host opts vulns for {host.get('ip_str')}: {raw_cves}")

        if isinstance(raw_cves, dict):
            cves = list(raw_cves.keys())
        elif isinstance(raw_cves, list):
            cves = raw_cves
        else:
            cves = []

        # grouped_cves = categorize_cves([{"id": cve_id} for cve_id in cves])
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
        "cves": host.get("opts", {}).get("vulns", []),
        "last_seen": last_seen,
        "services": services
    }
