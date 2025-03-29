# app/subdomain_enum.py
import requests
import re

def get_subdomains_from_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=10)

        if res.status_code != 200:
            print(f"[ERROR] crt.sh failed: {res.status_code}")
            return []

        data = res.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())

        return list(subdomains)

    except Exception as e:
        print(f"[ERROR] Subdomain enum failed: {e}")
        return []
