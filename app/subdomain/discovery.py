# Subdomain Discovery Module
# Uses: Subfinder, Assetfinder, DNS Bruteforce (parallel), Socket Fallback
# Optimized for maximum coverage with parallel execution

import subprocess
import socket
import os
import concurrent.futures
import time
from typing import List
from urllib.parse import urlparse

HOME = os.path.expanduser("~")

# Extended wordlist — 400+ entries for maximum coverage
BRUTE_SUBDOMAINS = [
    # Primary/Most common
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
    "vpn", "mail2", "new", "mysql", "old", "lists", "support",
    "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure",
    "demo", "cp", "calendar", "wiki", "web", "media", "email",
    "images", "img", "download", "dns", "stats", "dashboard", "portal",
    "manage", "start", "info", "app", "apps", "video", "sip",
    # API and dev
    "api", "api2", "api3", "rest", "graphql", "cdn", "remote",
    "server", "stage", "staging", "monitor", "photos", "tools",
    "cloud", "members", "bugs", "db", "ssh", "help", "community",
    "chat", "backup", "proxy", "cache", "analytics", "status",
    "gateway", "auth", "login", "signup", "account", "billing",
    "payments", "assets", "files", "alerts", "notifications",
    "webhook", "jobs", "careers", "about", "team", "contact",
    "legal", "privacy", "terms", "partners", "clients",
    "application", "production", "prod", "sandbox", "testing",
    "qa", "uat", "internal", "intranet", "extranet", "vpn2",
    "remote2", "citrix", "rdp", "terminal", "sftp", "git",
    "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy",
    "release", "code", "repo", "svn",
    # Business tools
    "jira", "confluence", "kb", "knowledge", "helpdesk", "ticket",
    "tickets", "crm", "erp", "hr", "finance", "accounting", "sales",
    "marketing", "reports", "reporting", "bi", "data", "ml", "ai",
    # Infrastructure
    "redis", "elasticsearch", "kibana", "grafana", "prometheus",
    "nagios", "docker", "k8s", "kubernetes", "vault", "consul",
    "traefik", "lb", "loadbalancer", "edge", "waf", "firewall",
    # Auth
    "mfa", "sso", "oauth", "saml", "ldap", "ad", "directory",
    "identity", "idp",
    # Mail
    "mail3", "smtp2", "relay", "bounce", "mailer", "newsletter",
    "imap2", "webmail2", "exchange", "owa",
    # E-commerce
    "store", "ecommerce", "cart", "checkout", "order", "orders",
    "product", "products", "catalog", "shipping", "pay", "payment",
    "invoice", "subscription",
    # Content
    "social", "board", "discuss", "talk", "press", "podcast",
    "stream", "live", "broadcast", "tv", "rss", "feed", "feeds",
    # Tech
    "map", "maps", "geo", "location", "search", "android", "ios",
    "pwa", "sdk", "developer", "developers",
    # Integration
    "integration", "zapier", "connector", "push", "notify", "sms",
    # Legacy
    "old2", "legacy", "archive", "recovery", "dr", "failover",
    "ha", "cluster", "node", "node2", "worker", "master", "replica",
    "primary", "secondary",
    # Regions
    "us", "eu", "asia", "uk", "de", "fr", "jp", "au", "ca", "sg",
    "us-east", "us-west", "eu-west", "ap-south", "global",
    # Additional
    "smtp3", "pop4", "roundcube", "horde", "tracking", "logistics",
    "supply", "invoices", "receipt", "plans", "pricing", "quote",
    "health", "ping", "uptime", "metrics", "logs", "log",
    "office", "workspace", "collaborate", "share", "upload",
    "uploads", "cdn2", "static2", "assets2", "preview", "review",
    "draft", "ssl", "tls",
    # More web patterns
    "www1", "www3", "web2", "web3", "site", "sites", "home",
    "host", "hosting", "server2", "server3", "app2", "app3",
    "mobile2", "touch", "wap", "pda",
    # Security
    "pentest", "security", "audit", "scan", "monitor2",
    # Monitoring
    "zabbix", "splunk", "logstash", "elk", "datadog", "newrelic",
    # Storage
    "storage", "s3", "bucket", "backup2", "archive2", "media2",
    # Microservices
    "service", "services", "microservice", "worker2",
    "queue", "broker", "bus", "event", "events",
    # Database
    "db2", "database", "mongo", "postgres", "mariadb",
    "oracle", "mssql", "sqlserver",
    # Additional common
    "test2", "test3", "dev2", "dev3", "uat2", "qa2",
    "preprod", "pre-prod", "preproduction",
    "canary", "green", "blue", "gray",
    "v1", "v2", "v3", "version",
    "corp", "corporate", "business", "enterprise",
    "public", "private", "internal2",
    "download2", "downloads", "dl", "mirror",
    "smtp4", "mail4", "mail5", "mta",
    "click", "track", "pixel", "beacon",
    "img2", "image", "images2", "photo", "photos",
    "js", "css", "fonts", "icons",
    "error", "errors", "status2", "health2",
    "console", "panel", "mgmt", "management",
    "root", "master2",
]

def normalize_domain(url: str) -> str:
    """Extract clean domain from URL."""
    parsed = urlparse(url)
    domain = parsed.hostname
    if not domain:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower().strip()

def resolve_domain(hostname: str, timeout: float = 2.0) -> str:
    """Resolve hostname to IP."""
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(original_timeout)

def run_subfinder(domain: str) -> List[str]:
    """Run Subfinder for passive subdomain enumeration."""
    possible_paths = [
        os.path.join(HOME, "go/bin/subfinder"),
        "/usr/local/bin/subfinder",
        "/usr/bin/subfinder",
        os.path.join(HOME, ".local/bin/subfinder"),
    ]
    subfinder_path = next(
        (p for p in possible_paths if os.path.exists(p) and os.access(p, os.X_OK)),
        None
    )
    if not subfinder_path:
        print("[Subfinder] Not found — skipping")
        return []
    try:
        print(f"[Subfinder] Using: {subfinder_path}")
        # Increased subprocess timeout to 300 seconds
        result = subprocess.run(
            [subfinder_path, "-d", domain, "-silent", "-timeout", "60", "-t", "50"],
            capture_output=True, text=True, timeout=300,
        )
        lines = [l.strip() for l in result.stdout.split("\n")
                 if l.strip() and domain in l and not l.startswith("[")]
        print(f"[Subfinder] Found: {len(lines)}")
        return lines
    except subprocess.TimeoutExpired:
        print("[Subfinder] Timeout")
        return []
    except Exception as e:
        print(f"[Subfinder] Error: {e}")
        return []

def run_assetfinder(domain: str) -> List[str]:
    """Run Assetfinder tool for passive subdomain discovery."""
    possible_paths = [
        "/usr/bin/assetfinder",
        "/usr/local/bin/assetfinder",
        os.path.join(HOME, "go/bin/assetfinder"),
        os.path.join(HOME, ".local/bin/assetfinder"),
    ]
    assetfinder_path = None
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            assetfinder_path = path
            break

    if not assetfinder_path:
        print("[Assetfinder] Not found — skipping")
        return []

    try:
        print(f"[Assetfinder] Using: {assetfinder_path}")
        # Increased timeout to 200 seconds
        result = subprocess.run(
            [assetfinder_path, "--subs-only", domain],
            capture_output=True, text=True, timeout=200,
        )
        lines = [l.strip() for l in result.stdout.split("\n") if l.strip() and domain in l]
        print(f"[Assetfinder] Found: {len(lines)}")
        return lines
    except subprocess.TimeoutExpired:
        print("[Assetfinder] Timeout")
        return []
    except Exception as e:
        print(f"[Assetfinder] Error: {e}")
        return []

def check_single_subdomain(args) -> str:
    """Check single subdomain — used in thread pool."""
    sub, domain = args
    hostname = f"{sub}.{domain}"
    ip = resolve_domain(hostname, timeout=2.0)
    if ip:
        return hostname
    return None

def dns_bruteforce(domain: str) -> List[str]:
    """
    Parallel DNS bruteforce using ThreadPoolExecutor.
    Uses 50 threads for speed.
    """
    found = []
    print(f"[DNS Bruteforce] Trying {len(BRUTE_SUBDOMAINS)} subdomains...")

    args_list = [(sub, domain) for sub in BRUTE_SUBDOMAINS]
    start_time = time.time()
    timeout_total = 400  # increased to 400 seconds (6.6 minutes)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_single_subdomain, args) for args in args_list]
        for future in concurrent.futures.as_completed(futures):
            if time.time() - start_time > timeout_total:
                print("[DNS Bruteforce] Global timeout reached, stopping.")
                break
            result = future.result(timeout=5)
            if result:
                ip = resolve_domain(result)
                found.append(result)
                print(f"[DNS Bruteforce] Found: {result} -> {ip or 'unknown'}")

    print(f"[DNS Bruteforce] Total: {len(found)}")
    return found

def socket_fallback(domain: str) -> List[str]:
    """
    Socket-based fallback for guaranteed basic subdomain coverage.
    Checks 30 most critical subdomains.
    """
    critical_subs = [
        "www", "mail", "ftp", "api", "dev", "staging", "blog",
        "shop", "admin", "portal", "app", "cdn", "static",
        "secure", "vpn", "remote", "ns1", "ns2", "mx",
        "smtp", "imap", "pop", "webmail", "support", "helpdesk",
        "test", "beta", "stage", "media",
    ]
    found = []
    print(f"[Socket Fallback] Checking {len(critical_subs)} critical subdomains...")

    args_list = [(sub, domain) for sub in critical_subs]

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(check_single_subdomain, args_list))

    for result in results:
        if result:
            found.append(result)
            ip = resolve_domain(result, timeout=4.0)
            print(f"[Socket Fallback] Found: {result} -> {ip or 'unknown'}")

    print(f"[Socket Fallback] Found: {len(found)}")
    return found

def discover_subdomains(url: str) -> dict:
    """
    Discover subdomains using 4 methods in sequence:
    1. Subfinder (passive)
    2. Assetfinder (passive)
    3. DNS Bruteforce (active, parallel, 400+ words)
    4. Socket Fallback (guaranteed 30 critical subs)

    Results deduplicated and IP-resolved.
    """
    domain = normalize_domain(url)
    print(f"\n{'='*50}")
    print(f"[Subdomain Discovery] Target: {domain}")
    print(f"{'='*50}")

    all_subdomains: set = set()

    all_subdomains.update(run_subfinder(domain))
    all_subdomains.update(run_assetfinder(domain))
    all_subdomains.update(dns_bruteforce(domain))
    all_subdomains.update(socket_fallback(domain))

    unique_subdomains = sorted(all_subdomains)

    print(f"{'='*50}")
    print(f"[TOTAL] Unique subdomains: {len(unique_subdomains)}")
    print(f"{'='*50}")

    results = []
    for sub in unique_subdomains:
        ip = resolve_domain(sub, timeout=4.0)
        results.append({
            "subdomain": sub,
            "ip": ip if ip else "unresolved",
        })

    return {
        "domain": domain,
        "subdomains": results,
        "total_found": len(results),
    }

discover_subdomains_advanced = discover_subdomains