from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from collections import defaultdict
from app.shodan_handler import scan_ip
from app.enrich import analyze_host
from app.subdomain_enum import get_subdomains_from_crtsh
from app.utils import resolve_domain

app = FastAPI()

# Allow cross-origin requests from React
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://yourusername.github.io/repo-name"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str

@app.post("/scan")
async def scan_target(request: ScanRequest):
    try:
        # print(f"[DEBUG] Received domain: {request.domain}")

        subdomains = get_subdomains_from_crtsh(request.domain)
        if request.domain not in subdomains:
            subdomains.append(request.domain)

        ip_to_subdomains = defaultdict(set)
        for sub in subdomains:
            resolved_ips = resolve_domain(sub)
            for ip in resolved_ips:
                ip_to_subdomains[ip].add(sub)

        if not ip_to_subdomains:
            return {"domain": request.domain, "results": [{"error": "No IPs found for domain or subdomains."}]}

        results = []
        seen_ips = set()  # ✅ Add this to avoid duplicate scans

        for ip, subdomain_set in ip_to_subdomains.items():
            if ip in seen_ips:
                continue  # ✅ Skip scanning duplicate IPs
            seen_ips.add(ip)

            # print(f"[DEBUG] Scanning {ip} (from: {list(subdomain_set)})")
            shodan_data = scan_ip(ip)
            analysis = analyze_host(shodan_data)
            analysis["ip"] = ip
            analysis["subdomains"] = list(subdomain_set)
            results.append(analysis)

        return {"domain": request.domain, "results": results}

    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return {"error": "Internal server error", "details": str(e)}


@app.get("/")
def root():
    return {"message": "Shodan Recon Tool is live"}
