from fastapi import FastAPI
from pydantic import BaseModel
from collections import defaultdict

from app.shodan_handler import scan_ip
from app.enrich import analyze_host
from app.subdomain_enum import get_subdomains_from_crtsh
from app.utils import resolve_domain

app = FastAPI()

class ScanRequest(BaseModel):
    domain: str

@app.post("/scan")
async def scan_target(request: ScanRequest):
    try:
        print(f"[DEBUG] Received domain: {request.domain}")

        # Step 1: Get subdomains
        subdomains = get_subdomains_from_crtsh(request.domain)
        if request.domain not in subdomains:
            subdomains.append(request.domain)

        # Step 2: Resolve each subdomain to IPs and build IP -> subdomain map
        ip_to_subdomains = defaultdict(set)
        for sub in subdomains:
            resolved_ips = resolve_domain(sub)
            for ip in resolved_ips:
                ip_to_subdomains[ip].add(sub)

        if not ip_to_subdomains:
            return {"domain": request.domain, "results": [{"error": "No IPs found for domain or subdomains."}]}

        # Step 3: Scan and enrich each unique IP
        results = []
        for ip, subdomain_set in ip_to_subdomains.items():
            print(f"[DEBUG] Scanning {ip} (from: {list(subdomain_set)})")
            shodan_data = scan_ip(ip)
            analysis = analyze_host(shodan_data)
            analysis["ip"] = ip
            analysis["subdomains"] = list(subdomain_set)
            results.append(analysis)

        return {"domain": request.domain, "results": results}

    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return {"error": "Internal server error", "details": str(e)}
