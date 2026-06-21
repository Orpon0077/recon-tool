import subprocess
import socket
import os

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"
os.environ["PATH"] = f"{GO_PATH}:{os.environ['PATH']}"

# ── Extended subdomain list ──
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
    "docs", "download", "upload", "files", "media", "cdn", "images",
    "audio", "stream", "live", "staging", "stage", "beta", "dev", "test",
    "demo", "sandbox", "community", "forum", "chat", "support", "help",
    "faq", "about", "contact", "careers", "jobs", "press", "news", "events",
    "ss", "preview", "staging", "stage", "beta", "dev", "test", "demo",
    "mail2", "mail3", "smtp2", "pop2", "imap2", "mx2", "mx3", "ns3", "ns4"
]

def run_cmd(cmd, timeout=20):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except:
        return ""

def discover_subdomains(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    
    all_subdomains = set()
    
    print(f"\n[Subdomain Discovery] Target: {domain}")
    print("=" * 50)
    
    # ── Tool 1: Assetfinder ──
    print("[Assetfinder] Running...")
    output = run_cmd(f"assetfinder --subs-only {domain}", timeout=25)
    count = 0
    for line in output.split('\n'):
        line = line.strip()
        if line and domain in line:
            line = line.replace('*.', '')
            if line not in all_subdomains:
                all_subdomains.add(line)
                count += 1
                print(f"[Assetfinder] Found: {line}")
    print(f"[Assetfinder] Total: {count}")
    
    # ── Tool 2: Subfinder ──
    print("[Subfinder] Running...")
    output = run_cmd(f"subfinder -d {domain} -silent", timeout=25)
    count = 0
    for line in output.split('\n'):
        line = line.strip()
        if line and domain in line:
            if line not in all_subdomains:
                all_subdomains.add(line)
                count += 1
                print(f"[Subfinder] Found: {line}")
    print(f"[Subfinder] Total: {count}")
    
    # ── Tool 3: Socket ──
    print("[Socket] Running...")
    socket_count = 0
    for sub in SOCKET_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            if full_domain not in all_subdomains:
                all_subdomains.add(full_domain)
                socket_count += 1
                print(f"[Socket] Found: {full_domain} -> {ip}")
        except:
            continue
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
