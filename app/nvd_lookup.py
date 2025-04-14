# app/nvd_lookup.py
import os
import requests
import time

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

API_KEY = os.getenv("NVD_API_KEY")  # Optional: set this in your .env later

HEADERS = {
    "apiKey": API_KEY
} if API_KEY else {}

def get_cve_details_from_nvd(cve_id):
    """Fetch a single CVE's metadata from NVD (title, description, CVSS)."""
    url = f"{NVD_BASE_URL}{cve_id}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code != 200:
            print(f"[NVD] Error {resp.status_code} for {cve_id}")
            return {}

        data = resp.json()
        item = data.get("result", {}).get("CVE_Items", [])[0]

        description = item["cve"]["description"]["description_data"][0]["value"]

        metrics = item.get("impact", {})
        cvss_score = None
        severity = "UNKNOWN"

        if "baseMetricV3" in metrics:
            cvss_score = metrics["baseMetricV3"]["cvssV3"]["baseScore"]
            severity = metrics["baseMetricV3"]["cvssV3"]["baseSeverity"]
        elif "baseMetricV2" in metrics:
            cvss_score = metrics["baseMetricV2"]["cvssV2"]["baseScore"]
            severity = metrics["baseMetricV2"]["severity"]

        return {
            "id": cve_id,
            "title": item["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"],
            "description": description,
            "cvss": cvss_score,
            "severity": severity
        }
    except Exception as e:
        print(f"[NVD] Failed to fetch {cve_id}: {e}")
        return {}
