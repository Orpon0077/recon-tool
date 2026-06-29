import subprocess
import socket
import os

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"
os.environ["PATH"] = f"{GO_PATH}:{os.environ['PATH']}"

# ── Extensive Subdomain List (300+ common subdomains) ──
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
    "mail2", "mail3", "smtp2", "pop2", "imap2", "mx2", "mx3", "ns3", "ns4",
    "cdn2", "cdn3", "api2", "api3", "dev2", "test2", "stage2", "blog2",
    "shop2", "shop3", "support2", "login2", "signup2", "app2", "app3",
    "stats", "monitor2", "analytics2", "dashboard2", "portal2", "tools2",
    "waf2", "link2", "ftp2", "smtp3", "pop3", "imap3", "mx4", "ns5",
    "cpanel2", "whm2", "webmail2", "autodiscover2", "webdisk2",
    "backup2", "cache2", "proxy2", "remote2", "server2", "cloud2",
    "members2", "bugs2", "db2", "ssh2", "kernel2", "mobi2", "web2",
    "docs2", "download2", "upload2", "files2", "media2", "cdn3",
    "images2", "audio2", "stream2", "live2", "faq2", "about2", "contact2",
    "careers2", "jobs2", "press2", "news2", "events2", "preview2",
    "community2", "forum2", "chat2", "help2"
]

def run_cmd(cmd, timeout=35):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except:
        return ""

def discover_subdomains(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.replace("www.", "")
    
    all_subdomains = set()
    
    # ── Add root domain ──
    try:
        root_ip = socket.gethostbyname(domain)
        all_subdomains.add(domain)
        print(f"[Root] {domain} -> {root_ip}")
    except:
        pass
    
    print(f"\n[Subdomain Discovery] Target: {domain}")
    print("=" * 50)
    
    # ── Assetfinder ──
    print("[Assetfinder] Running (35s)...")
    output = run_cmd(f"assetfinder --subs-only {domain}", timeout=35)
    count = 0
    for line in output.split('\n'):
        line = line.strip()
        if line and domain in line:
            line = line.replace('*.', '')
            if line not in all_subdomains:
                all_subdomains.add(line)
                count += 1
                print(f"[Assetfinder] {line}")
    print(f"[Assetfinder] Total: {count}")
    
    # ── Subfinder ──
    print("[Subfinder] Running (35s)...")
    output = run_cmd(f"subfinder -d {domain} -silent", timeout=35)
    count = 0
    for line in output.split('\n'):
        line = line.strip()
        if line and domain in line:
            if line not in all_subdomains:
                all_subdomains.add(line)
                count += 1
                print(f"[Subfinder] {line}")
    print(f"[Subfinder] Total: {count}")
    
    # ── Socket ──
    print("[Socket] Running...")
    socket_count = 0
    for sub in SOCKET_SUBDOMAINS:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            if full not in all_subdomains:
                all_subdomains.add(full)
                socket_count += 1
                print(f"[Socket] {full} -> {ip}")
        except:
            continue
    print(f"[Socket] Found: {socket_count}")
    
    # ── Results (NO LIMIT - ALL subdomains) ──
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
