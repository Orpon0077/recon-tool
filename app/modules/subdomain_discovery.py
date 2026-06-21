import subprocess
import socket
import os
import time

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"
os.environ["PATH"] = f"{GO_PATH}:{os.environ['PATH']}"

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
    "cloud", "members", "bugs", "db", "ssh", "kernel", "mobi", "web",
    "ss", "preview"
]

def run_cmd(cmd, timeout=25):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except:
        return ""

def discover_subdomains(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    
    all_subdomains = set()
    
    # ── Always add root domain ──
    try:
        root_ip = socket.gethostbyname(domain)
        all_subdomains.add(domain)
        print(f"[Root] {domain} -> {root_ip}")
    except:
        pass
    
    print(f"\n[Subdomain Discovery] Target: {domain}")
    print("=" * 50)
    
    # ── Assetfinder ──
    print("[Assetfinder] Running (25s)...")
    output = run_cmd(f"assetfinder --subs-only {domain}", timeout=25)
    for line in output.split('\n'):
        line = line.strip()
        if line and domain in line:
            line = line.replace('*.', '')
            if line not in all_subdomains:
                all_subdomains.add(line)
                print(f"[Assetfinder] {line}")
    
    # ── Subfinder ──
    print("[Subfinder] Running (25s)...")
    output = run_cmd(f"subfinder -d {domain} -silent", timeout=25)
    for line in output.split('\n'):
        line = line.strip()
        if line and domain in line:
            if line not in all_subdomains:
                all_subdomains.add(line)
                print(f"[Subfinder] {line}")
    
    # ── Socket ──
    print("[Socket] Running...")
    for sub in SOCKET_SUBDOMAINS:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            if full not in all_subdomains:
                all_subdomains.add(full)
                print(f"[Socket] {full} -> {ip}")
        except:
            continue
    
    # ── Results ──
    results = []
    for sub in sorted(all_subdomains):
        try:
            ip = socket.gethostbyname(sub)
            results.append({"subdomain": sub, "ip": ip})
        except:
            results.append({"subdomain": sub, "ip": "unresolved"})
    
    print("=" * 50)
    print(f"[TOTAL] {len(results)} subdomains")
    print("=" * 50)
    
    return {
        "domain": domain,
        "subdomains": results,
        "total_found": len(results)
    }
