import socket
import requests
def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return [ip]
    except Exception as e:
        print(f"Error resolving domain: {e}")
        return []
    


def search_cves_by_ids(cve_ids):
    enriched = []
    for cve_id in cve_ids:
        enriched.append({
            "id": cve_id,
            "title": f"Placeholder title for {cve_id}",
            "description": "",
            "cvss": None,
            "references": [],
        })
    return enriched
