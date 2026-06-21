from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import subprocess
import socket
import re
from urllib.parse import urlparse
import requests
import dns.resolver

router = APIRouter(prefix="/api", tags=["subdomain"])

class SubdomainRequest(BaseModel):
    url: str

def get_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]
    domain = domain.replace('www.', '')
    return domain

def run_subfinder(domain: str) -> List[str]:
    """Run subfinder for passive subdomain enumeration"""
    try:
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent'],
            capture_output=True,
            text=True,
            timeout=20
        )
        if result.stdout:
            return [line.strip() for line in result.stdout.split('\n') if line.strip()]
    except Exception as e:
        print(f"[Subfinder] Error: {e}")
    return []

def run_assetfinder(domain: str) -> List[str]:
    """Run assetfinder for additional subdomains"""
    try:
        result = subprocess.run(
            ['assetfinder', '--subs-only', domain],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.stdout:
            lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            return lines
    except Exception as e:
        print(f"[Assetfinder] Error: {e}")
    return []

def dns_bruteforce(domain: str) -> List[str]:
    """Basic DNS brute force with common subdomains"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
        'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
        'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp',
        'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
        'download', 'dns', 'stats', 'dashboard', 'portal', 'manage', 'start',
        'info', 'apps', 'video', 'sip', 'api', 'cdn', 'remote', 'server',
        'stage', 'monitor', 'photos', 'tools', 'cloud', 'members', 'bugs',
        'db', 'ssh', 'kernel', 'mobi', 'help', 'stage2'
    ]
    found = []
    for sub in common_subdomains:
        try:
            target = f"{sub}.{domain}"
            socket.gethostbyname(target)
            found.append(target)
        except:
            continue
    return found

def resolve_ip(hostname: str) -> Optional[str]:
    """Resolve hostname to IP"""
    try:
        return socket.gethostbyname(hostname)
    except:
        return None

def get_http_status(subdomain: str) -> Optional[int]:
    """Get HTTP status for subdomain"""
    try:
        for protocol in ['https', 'http']:
            try:
                response = requests.get(
                    f"{protocol}://{subdomain}",
                    timeout=3,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                return response.status_code
            except:
                continue
    except:
        pass
    return None

def scan_ports(ip: str, ports: List[int] = None) -> List[int]:
    """Scan common ports on IP"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

def detect_tech_on_subdomain(subdomain: str) -> List[str]:
    """Detect basic technologies on subdomain"""
    techs = []
    try:
        for protocol in ['https', 'http']:
            try:
                resp = requests.get(
                    f"{protocol}://{subdomain}",
                    timeout=2,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                server = resp.headers.get('server', '')
                if server:
                    techs.append(server)
                powered = resp.headers.get('x-powered-by', '')
                if powered:
                    techs.append(powered)
                break
            except:
                continue
    except:
        pass
    return techs

@router.post("/subdomain")
async def discover_subdomains(request: SubdomainRequest):
    """Discover subdomains for a target domain"""
    domain = get_domain(request.url)
    print(f"\n[Subdomain Discovery] Target: {domain}")
    print("=" * 50)
    
    all_subdomains = set()
    
    # 1. Subfinder
    print("[Subfinder] Running (20s timeout)...")
    subfinder_results = await asyncio.to_thread(run_subfinder, domain)
    all_subdomains.update(subfinder_results)
    print(f"[Subfinder] Found: {len(subfinder_results)}")
    
    # 2. Assetfinder
    print("[Assetfinder] Running (15s timeout)...")
    assetfinder_results = await asyncio.to_thread(run_assetfinder, domain)
    all_subdomains.update(assetfinder_results)
    print(f"[Assetfinder] Found: {len(assetfinder_results)}")
    
    # 3. DNS Bruteforce
    print("[DNS Bruteforce] Running...")
    dns_results = await asyncio.to_thread(dns_bruteforce, domain)
    all_subdomains.update(dns_results)
    print(f"[DNS Bruteforce] Found: {len(dns_results)}")
    
    # Remove duplicates and sort
    all_subdomains = sorted(all_subdomains)
    print(f"[Total] Unique: {len(all_subdomains)}")
    
    # Limit to prevent timeout
    subdomains_to_process = all_subdomains[:30]
    print(f"[Processing] First {len(subdomains_to_process)} subdomains...")
    
    # Process each subdomain
    results = []
    
    for i, sub in enumerate(subdomains_to_process, 1):
        print(f"[Processing] {i}/{len(subdomains_to_process)}: {sub}")
        
        result = {
            "subdomain": sub,
            "ip": None,
            "http_status": None,
            "technologies": [],
            "open_ports": [],
            "screenshot": None
        }
        
        # Get IP
        ip = resolve_ip(sub)
        if ip:
            result["ip"] = ip
            
            # Scan ports on IP
            ports = await asyncio.to_thread(scan_ports, ip)
            result["open_ports"] = ports
        
        # Get HTTP status
        status = get_http_status(sub)
        if status:
            result["http_status"] = status
        
        # Detect technologies
        techs = await asyncio.to_thread(detect_tech_on_subdomain, sub)
        if techs:
            result["technologies"] = techs
        
        results.append(result)
    
    response_data = {
        "domain": domain,
        "total_found": len(results),
        "subdomains": results,
        "error": None
    }
    
    print(f"[Done] Total: {len(results)} subdomains processed")
    print("=" * 50)
    
    return response_data
