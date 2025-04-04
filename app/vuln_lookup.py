import os
import requests
import logging
from dotenv import load_dotenv
load_dotenv()

VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

if not VULNERS_API_KEY:
    print("[WARNING] Vulners API key not found!")

VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"


def search_cves(product: str, version: str):
    if not VULNERS_API_KEY or not product or not version:
        return []

    queries = [
        f"httpd:{version}",
        f"apache:httpd:{version}",
        f"Apache httpd {version}",
        f"Apache {version}",
    ]

    seen = set()
    deduped_results = []

    for query in queries:
        print(f"[DEBUG] Trying query: {query}")

        response = requests.get(
            "https://vulners.com/api/v3/search/lucene/",
            params={"query": query, "apiKey": VULNERS_API_KEY}
        )

        data = response.json()
        search_results = data.get("data", {}).get("search", [])

        for cve in search_results:
            cve_id = cve.get("id") or cve.get("_source", {}).get("id")
            title = cve.get("title") or cve.get("_source", {}).get("title", "")
            key = f"{cve_id}:{title}"

            if key not in seen:
                seen.add(key)
                deduped_results.append(cve)

    return deduped_results
