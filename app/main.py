from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from collections import defaultdict
from app.shodan_handler import scan_ip
from app.enrich import analyze_host
from app.subdomain_enum import get_subdomains_from_crtsh
from app.utils import resolve_domain
import logging
import json

logger = logging.getLogger(__name__)
app = FastAPI()

# Allow cross-origin requests from React
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://scarlett-k.github.io"
    ],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok"}


class ScanRequest(BaseModel):
    domain: str


@app.post("/scan")
async def scan_target(request: ScanRequest):
    try:
        subdomains = get_subdomains_from_crtsh(request.domain)
        if request.domain not in subdomains:
            subdomains.append(request.domain)

        ip_to_subdomains = defaultdict(set)
        for sub in subdomains:
            resolved_ips = resolve_domain(sub)
            for ip in resolved_ips:
                ip_to_subdomains[ip].add(sub)

        if not ip_to_subdomains:
            return []

        results = []
        seen_ips = set()

        for ip, subdomain_set in ip_to_subdomains.items():
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            shodan_data = scan_ip(ip)
            print("[DEBUG] Raw Shodan response:")
            print(json.dumps(shodan_data, indent=2), flush=True)

            analysis = analyze_host(shodan_data)
            analysis["ip"] = ip
            analysis["subdomains"] = list(subdomain_set)
            results.append(analysis)

        # ✅ Option A: only return the list directly
        return results

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"error": "Internal server error", "details": str(e)}


@app.get("/")
def root():
    return {"message": "Shodan Recon Tool is live"}
