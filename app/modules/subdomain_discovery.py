import subprocess
import socket
import os
import time

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"

SOCKET_SUBDOMAINS = [
    "www", "mail", "blog", "api", "admin", "dev", "test", "shop", "support",
    "login", "signup", "app", "cdn", "static", "assets", "img", "video",
    "media", "docs", "drive", "calendar", "photos", "news", "maps",
    "accounts", "office", "portal", "tools", "marketing", "waf", "link",
    "ftp", "smtp", "pop", "imap", "mx", "ns1", "ns2", "cpanel", "whm",
    "webmail", "autodiscover", "webdisk", "staging", "stage", "beta",
    "demo", "sandbox", "community", "forum", "chat", "help", "remote",
    "server", "backup", "cache", "proxy", "monitor", "analytics", "status",
    "dashboard", "manage", "start", "info", "apps", "video", "sip",
    "cloud", "members", "bugs", "db", "ssh", "kernel", "mobi", "web"
]

def resolve_with_retry(domain: str, retries: int = 2) -> str:
    for i in range(retries):
        try:
            return socket.gethostbyname(domain)
        except:
            if i < retries - 1:
                time.sleep(0.3)
    return None

def discover_subdomains(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    
    all_subdomains = set()
    
    print(f"\n[Subdomain Discovery] Target: {domain}")
    print("=" * 50)
    
    # ── Tool 1: Subfinder (with error handling) ──
    subfinder_path = f"{GO_PATH}/subfinder"
    if os.path.exists(subfinder_path):
        try:
            print("[Subfinder] Running (30s timeout)...")
            result = subprocess.run(
                [subfinder_path, "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=30
            )
            count = 0
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and domain in line:
                    if line not in all_subdomains:
                        all_subdomains.add(line)
                        count += 1
                        print(f"[Subfinder] Found: {line}")
            print(f"[Subfinder] Total: {count}")
        except subprocess.TimeoutExpired:
            print("[Subfinder] ⏰ Timeout - continuing with other tools")
        except Exception as e:
            print(f"[Subfinder] Error: {e}")
    else:
        print("[Subfinder] Not installed")
    
    # ── Tool 2: Assetfinder (with error handling) ──
    assetfinder_path = "/usr/bin/assetfinder"
    if os.path.exists(assetfinder_path):
        try:
            print("[Assetfinder] Running (15s timeout)...")
            result = subprocess.run(
                [assetfinder_path, "--subs-only", domain],
                capture_output=True, text=True, timeout=15
            )
            count = 0
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and domain in line:
                    if line not in all_subdomains:
                        all_subdomains.add(line)
                        count += 1
                        print(f"[Assetfinder] Found: {line}")
            print(f"[Assetfinder] Total: {count}")
        except subprocess.TimeoutExpired:
            print("[Assetfinder] ⏰ Timeout - continuing with socket")
        except Exception as e:
            print(f"[Assetfinder] Error: {e}")
    else:
        print("[Assetfinder] Not installed")
    
    # ── Tool 3: Socket (always works) ──
    print("[Socket] Running...")
    socket_count = 0
    for sub in SOCKET_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        ip = resolve_with_retry(full_domain, retries=2)
        if ip:
            if full_domain not in all_subdomains:
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
