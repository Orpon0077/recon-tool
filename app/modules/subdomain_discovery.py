import subprocess
import socket
import os
import time

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"

# Socket subdomain list
SOCKET_SUBDOMAINS = [
    "www", "mail", "blog", "api", "admin", "dev", "test",
    "shop", "support", "login", "signup", "app", "cdn",
    "static", "assets", "img", "video", "media", "docs",
    "drive", "calendar", "photos", "news", "maps", "accounts",
    "office", "portal", "tools", "marketing", "waf", "link",
    "ftp", "smtp", "pop", "imap", "mx", "ns1", "ns2",
    "cpanel", "whm", "webmail", "autodiscover", "webdisk",
    "staging", "stage", "beta", "demo", "sandbox", "dev",
    "community", "forum", "chat", "help", "support",
    "remote", "server", "backup", "cache", "proxy", "monitor"
]

def resolve_with_retry(domain: str, retries: int = 2) -> str:
    """DNS resolution with retry"""
    for i in range(retries):
        try:
            return socket.gethostbyname(domain)
        except:
            time.sleep(0.5)
    return None

def discover_subdomains(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    
    all_subdomains = set()
    
    print(f"\n[Subdomain Discovery] Target: {domain}")
    print("=" * 50)
    
    # ── Tool 1: Subfinder (45s timeout) ──
    subfinder_path = f"{GO_PATH}/subfinder"
    if os.path.exists(subfinder_path):
        try:
            print("[Subfinder] Running (45s timeout)...")
            result = subprocess.run(
                [subfinder_path, "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=45
            )
            count = 0
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and domain in line:
                    all_subdomains.add(line)
                    count += 1
                    print(f"[Subfinder] Found: {line}")
            print(f"[Subfinder] Total: {count}")
        except subprocess.TimeoutExpired:
            print("[Subfinder] Timeout - using socket only")
        except Exception as e:
            print(f"[Subfinder] Error: {e}")
    else:
        print("[Subfinder] Not installed")
    
    # ── Tool 2: Socket with retry ──
    print("[Socket] Running...")
    socket_count = 0
    for sub in SOCKET_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        ip = resolve_with_retry(full_domain)
        if ip:
            all_subdomains.add(full_domain)
            socket_count += 1
            print(f"[Socket] Found: {full_domain} -> {ip}")
    print(f"[Socket] Found: {socket_count}")
    
    # ── Format Results ──
    final_results = []
    for sub in sorted(all_subdomains):
        try:
            ip = socket.gethostbyname(sub)
            final_results.append({"subdomain": sub, "ip": ip})
        except:
            final_results.append({"subdomain": sub, "ip": "unresolved"})
    
    print("=" * 50)
    print(f"[TOTAL] Unique subdomains: {len(final_results)}")
    print("=" * 50)
    
    return {
        "domain": domain,
        "subdomains": final_results,
        "total_found": len(final_results)
    }

discover_subdomains_advanced = discover_subdomains
