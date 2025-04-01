import socket

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return [ip]
    except Exception as e:
        print(f"Error resolving domain: {e}")
        return []