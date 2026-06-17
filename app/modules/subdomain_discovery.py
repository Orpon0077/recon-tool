import subprocess
import socket
import os

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"

# Extended Socket subdomain list
SOCKET_SUBDOMAINS = [
    "www", "mail", "blog", "api", "admin", "dev", "test",
    "shop", "support", "login", "signup", "app", "cdn",
    "static", "assets", "img", "video", "media", "docs",
    "drive", "calendar", "photos", "news", "maps", "accounts",
    "office", "portal", "tools", "marketing", "waf", "link",
    "ftp", "smtp", "pop", "imap", "mx", "ns1", "ns2",
    "cpanel", "whm", "webmail", "autodiscover", "webdisk"
]

def discover_subdomains(domain: str) -> dict:
    """Subdomain discovery - Subfinder (extended timeout) + Socket"""
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    
    all_subdomains = set()
    
    print(f"[Subdomain] Scanning {domain}...")
    
    # ── Tool 1: Subfinder (40 second timeout) ──
    subfinder_path = f"{GO_PATH}/subfinder"
    if os.path.exists(subfinder_path):
        try:
            print("[Subdomain] Running Subfinder (40s timeout)...")
            result = subprocess.run(
                [subfinder_path, "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=40
            )
            subfinder_count = 0
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if line and domain in line:
                    all_subdomains.add(line)
                    subfinder_count += 1
            print(f"[Subfinder] Found {subfinder_count} subdomains")
        except subprocess.TimeoutExpired:
            print("[Subfinder] Timeout - continuing with partial results")
        except Exception as e:
            print(f"[Subfinder] Error: {e}")
    else:
        print("[Subfinder] Not installed")
    
    # ── Tool 2: Socket Extended List ──
    print("[Subdomain] Socket scanning...")
    socket_count = 0
    for sub in SOCKET_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            if full_domain not in all_subdomains:
                all_subdomains.add(full_domain)
                socket_count += 1
        except:
            pass
    print(f"[Socket] Found {socket_count} subdomains")
    
    # Format results
    final_results = []
    for sub in sorted(all_subdomains):
        try:
            ip = socket.gethostbyname(sub)
            final_results.append({"subdomain": sub, "ip": ip})
        except:
            final_results.append({"subdomain": sub, "ip": "unresolved"})
    
    print(f"[Subdomain] Total found: {len(final_results)}")
    
    return {
        "domain": domain,
        "subdomains": final_results,
        "total_found": len(final_results)
    }

discover_subdomains_advanced = discover_subdomains
