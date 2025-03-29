import os
import requests
import logging
from dotenv import load_dotenv
load_dotenv()

VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

if not VULNERS_API_KEY:
    print("[WARNING] Vulners API key not found!")

VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"




VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

def search_cves(product: str, version: str):
    if not VULNERS_API_KEY or not product or not version:
        return []
    queries = [
        f"httpd:{version}",
        f"apache:httpd:{version}",
        f"Apache httpd {version}",
        f"Apache {version}",
    ]

    for query in queries:
        print(f"[DEBUG] Trying query: {query}")
        
        # Send the request to Vulners here, just like you already do
        response = requests.get(
            "https://vulners.com/api/v3/search/lucene/",
            params={"query": query, "apiKey": VULNERS_API_KEY}
        )

        data = response.json()
        print(f"[DEBUG] Vulners raw response: {data}")

        # If any results are found, break and return them
        if data.get("data", {}).get("search"):
            return data["data"]["search"]

    # Fallback: no CVEs found
    return []
