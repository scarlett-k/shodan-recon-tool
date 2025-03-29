import shodan
import os
from dotenv import load_dotenv

load_dotenv()
api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))

def scan_ip(ip):
    try:
        host = api.host(ip)
        return host
    except shodan.APIError as e:
        print(f"Shodan error: {e}")
        return {}
