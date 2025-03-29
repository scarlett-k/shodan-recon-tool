from app.vuln_lookup import search_cves

def analyze_host(host):
    vulns = host.get("vulns")
    ip = host.get("ip_str")
    org = host.get("org", "Unknown")
    country = host.get("location", {}).get("country_name", "Unknown")
    ports = host.get("ports", [])
    last_seen = host.get("last_update", "")
    flagged_ports = [p for p in ports if p in [21, 22, 23, 3389]]

    services = []
    for item in host.get("data", []):
        product = item.get("product")
        version = item.get("version")
        port = item.get("port")

        print(f"[DEBUG] Looking up CVEs for {product} {version} on port {port}")
        cves = search_cves(product, version) if product and version else []
        print(f"[DEBUG] Found {len(cves)} CVEs")
        print(f"[DEBUG] CVEs to be added: {cves}")

        services.append({
            "port": port,
            "product": product,
            "version": version,
            "extra_cves": cves  # <- this must be the list returned by search_cves()
        })

    return {
        "ip": ip,
        "org": org,
        "country": country,
        "ports": ports,
        "flagged_ports": flagged_ports,
        "cves": vulns if isinstance(vulns, list) else list(vulns.keys()) if isinstance(vulns, dict) else [],
        "last_seen": last_seen,
        "services": services
    }
