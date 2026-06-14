import subprocess
import socket
import os
import requests
import re
import hashlib

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"

def get_subdomain_details(subdomain: str) -> dict:
    """Get detailed info for a subdomain including screenshot path"""
    details = {
        "http_status": "N/A",
        "technologies": [],
        "open_ports": [],
        "screenshot": None
    }
    
    try:
        url = f"https://{subdomain}"
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        details["http_status"] = response.status_code
        
        # Technology detection
        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text.lower()
        
        if 'server' in headers:
            details["technologies"].append(f"Server: {headers['server']}")
        if 'x-powered-by' in headers:
            details["technologies"].append(f"Backend: {headers['x-powered-by']}")
        if 'react' in html or '_react' in html:
            details["technologies"].append("React")
        if '_next' in html or 'next/dist' in html:
            details["technologies"].append("Next.js")
        
        # Port scan for subdomain
        common_ports = [80, 443, 22, 21, 25, 3306, 3389, 5432, 8080, 8443]
        for port in common_ports[:5]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                ip = socket.gethostbyname(subdomain)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    service = {80: "HTTP", 443: "HTTPS", 22: "SSH"}.get(port, "unknown")
                    details["open_ports"].append(f"{port}/{service}")
            except:
                pass
        
        # Generate screenshot path using same method as main screenshot module
        screenshot_hash = hashlib.md5(url.encode()).hexdigest()
        details["screenshot"] = f"screenshots/{screenshot_hash}.png"
        
        # Verify if screenshot file actually exists
        screenshot_path = os.path.join(os.path.dirname(__file__), "..", "..", "static", f"screenshots/{screenshot_hash}.png")
        if not os.path.exists(screenshot_path):
            details["screenshot"] = None
            
    except Exception as e:
        print(f"Error getting details for {subdomain}: {e}")
    
    return details

def discover_subdomains(domain: str) -> dict:
    """Ultimate subdomain discovery with full details"""
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    all_subdomains = set()
    
    print(f"\n{'='*60}")
    print(f"[Subdomain Discovery] Target: {domain}")
    print(f"{'='*60}")
    
    # Tool 1: Subfinder
    subfinder_path = f"{GO_PATH}/subfinder"
    if os.path.exists(subfinder_path):
        print("[1/3] Subfinder scanning...")
        try:
            result = subprocess.run(
                [subfinder_path, "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=90
            )
            subfinder_count = 0
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if line and domain in line:
                    all_subdomains.add(line)
                    subfinder_count += 1
            print(f"      Found: {subfinder_count} subdomains")
        except Exception as e:
            print(f"      Error: {e}")
    
    # Tool 2: Assetfinder
    assetfinder_path = f"{GO_PATH}/assetfinder"
    if os.path.exists(assetfinder_path):
        print("[2/3] Assetfinder scanning...")
        try:
            result = subprocess.run(
                [assetfinder_path, "--subs-only", domain],
                capture_output=True, text=True, timeout=30
            )
            assetfinder_count = 0
            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if line and domain in line:
                    all_subdomains.add(line)
                    assetfinder_count += 1
            print(f"      Found: {assetfinder_count} subdomains")
        except Exception as e:
            print(f"      Error: {e}")
    
    # Tool 3: Socket resolution
    print("[3/3] Socket scanning...")
    common_subs = [
        "www", "mail", "drive", "docs", "calendar", "photos", "news", "maps",
        "accounts", "admin", "api", "blog", "shop", "support", "login", "signup",
        "app", "dev", "test", "cdn", "static", "assets", "img", "video", "media",
        "dashboard", "panel", "console", "manage", "analytics", "stats", "status",
        "help", "faq", "contact", "about", "team", "careers", "jobs", "cloud",
        "ads", "play", "books", "scholar", "groups", "images", "translate",
        "keep", "meet", "classroom", "sites", "forms", "script", "workspace",
        "office", "portal", "tools", "marketing", "waf", "link"
    ]
    
    socket_count = 0
    for sub in common_subs:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            if full_domain not in all_subdomains:
                all_subdomains.add(full_domain)
                socket_count += 1
        except:
            pass
    print(f"      Found: {socket_count} additional subdomains")
    
    # Get detailed info for each subdomain
    print("\n[Fetching subdomain details...]")
    final_results = []
    subdomains_list = sorted(all_subdomains)
    total = len(subdomains_list)
    
    for i, sub in enumerate(subdomains_list):
        if i >= 50:
            break
        print(f"      [{i+1}/{min(total,50)}] Analyzing: {sub}")
        details = get_subdomain_details(sub)
        try:
            ip = socket.gethostbyname(sub)
        except:
            ip = "unresolved"
        
        final_results.append({
            "subdomain": sub,
            "ip": ip,
            "http_status": details["http_status"],
            "technologies": details["technologies"],
            "open_ports": details["open_ports"],
            "screenshot": details["screenshot"]
        })
    
    print(f"\n{'='*60}")
    print(f"[Total Subdomains Found: {len(final_results)}]")
    print(f"{'='*60}")
    
    return {
        "domain": domain,
        "subdomains": final_results,
        "total_found": len(final_results)
    }

discover_subdomains_advanced = discover_subdomains
