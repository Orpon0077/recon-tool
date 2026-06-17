import subprocess
import socket
import os

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"

# Socket fallback list
SOCKET_SUBDOMAINS = [
    "www", "mail", "blog", "api", "admin", "dev", "test",
    "shop", "support", "login", "signup", "app", "cdn",
    "static", "assets", "img", "video", "media", "docs",
    "drive", "calendar", "photos", "news", "maps", "accounts",
    "office", "portal", "tools", "marketing", "waf", "link"
]

def discover_subdomains(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    
    all_subdomains = set()
    
    print(f"\n[Subdomain Discovery] Target: {domain}")
    print("=" * 50)
    
    # ── Subfinder (30s timeout) ──
    subfinder_path = f"{GO_PATH}/subfinder"
    if os.path.exists(subfinder_path):
        try:
            print("[Subfinder] Running (30s timeout)...")
            result = subprocess.run(
                [subfinder_path, "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=30
            )
            count = 0
            lines = result.stdout.split('\n')
            for line in lines:
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
        print(f"[Subfinder] Not found")
    
    # ── Socket Fallback ──
    print("[Socket] Running...")
    socket_count = 0
    for sub in SOCKET_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            all_subdomains.add(full_domain)
            socket_count += 1
            print(f"[Socket] Found: {full_domain} -> {ip}")
        except:
            pass
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
