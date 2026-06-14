import socket

# Extended common subdomains list
COMMON_SUBDOMAINS = [
    "www", "mail", "blog", "autodiscover", "admin", "api", "ftp", "dev", 
    "test", "shop", "support", "login", "signup", "app", "webmail", 
    "cpanel", "whm", "webdisk", "ns1", "ns2", "m", "imap", "smtp", "pop",
    "calendar", "docs", "drive", "photos", "news", "maps", "accounts",
    "office", "portal", "tools", "marketing", "waf", "link"
]

def discover_subdomains(domain: str) -> dict:
    """Simple socket-based subdomain discovery (100% working)"""
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    discovered = []
    
    print(f"[Subdomain] Scanning {domain}...")
    
    for sub in COMMON_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            discovered.append({"subdomain": full_domain, "ip": ip})
            print(f"[Subdomain] ✓ Found: {full_domain} -> {ip}")
        except:
            pass
    
    print(f"[Subdomain] Total found: {len(discovered)}")
    
    return {
        "domain": domain,
        "subdomains": discovered,
        "total_found": len(discovered)
    }

discover_subdomains_advanced = discover_subdomains
