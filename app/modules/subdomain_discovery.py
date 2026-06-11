# ── Subdomain Discovery Module ──────────────────────────────
import socket
import dns.resolver
from typing import List, Dict

# বড় সাবডোমেইন লিস্ট
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum",
    "news", "vpn", "ns3", "mail2", "new", "mysql", "old", "lists",
    "support", "mobile", "mx", "static", "docs", "beta", "shop",
    "sql", "secure", "demo", "cp", "calendar", "wiki", "web",
    "media", "email", "images", "img", "download", "dns", "stats",
    "dashboard", "portal", "manage", "start", "info", "apps",
    "video", "sip", "dns2", "api", "cdn", "remote", "server",
    "panel", "stage", "upload", "cache", "git", "internal",
    "backup", "proxy", "tools", "chat", "storage", "db",
    "files", "members", "root", "cdn2", "vps", "login", "signup",
    "register", "auth", "account", "user", "profile", "settings",
    "dashboard", "analytics", "report", "reports", "stat", "status",
    "help", "faq", "support", "contact", "about", "team", "careers",
    "jobs", "newsletter", "press", "media", "resources", "download",
    "upload", "share", "link", "short", "url", "redirect", "proxy"
]

def resolve_subdomain(subdomain: str, domain: str) -> dict:
    full_domain = f"{subdomain}.{domain}"
    try:
        # Try A record
        answers = dns.resolver.resolve(full_domain, 'A')
        ip = str(answers[0])
        return {
            "subdomain": full_domain,
            "ip": ip,
            "resolves": True
        }
    except:
        try:
            # Try CNAME record
            answers = dns.resolver.resolve(full_domain, 'CNAME')
            target = str(answers[0])
            return {
                "subdomain": full_domain,
                "ip": f"CNAME → {target}",
                "resolves": True
            }
        except:
            return None

def discover_subdomains(domain: str) -> dict:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    discovered = []
    
    print(f"[Subdomain] Scanning {domain} with {len(COMMON_SUBDOMAINS)} common subdomains...")
    
    for sub in COMMON_SUBDOMAINS:
        result = resolve_subdomain(sub, domain)
        if result:
            discovered.append(result)
            print(f"[Subdomain] Found: {result['subdomain']} → {result['ip']}")
    
    return {
        "domain": domain,
        "subdomains": discovered,
        "total_found": len(discovered)
    }

def discover_subdomains_advanced(domain: str) -> dict:
    return discover_subdomains(domain)
