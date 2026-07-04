import subprocess
import socket
import os
import time
from typing import List
from urllib.parse import urlparse

HOME = os.path.expanduser("~")
GO_PATH = f"{HOME}/go/bin"

# ২০০+ subdomain wordlist
BRUTE_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
    'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
    'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp',
    'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
    'download', 'dns', 'stats', 'dashboard', 'portal', 'manage', 'start',
    'info', 'apps', 'video', 'sip', 'api', 'cdn', 'remote', 'server',
    'stage', 'monitor', 'photos', 'tools', 'cloud', 'members', 'bugs',
    'db', 'ssh', 'help', 'community', 'chat', 'backup', 'proxy', 'cache',
    'analytics', 'status', 'gateway', 'auth', 'login', 'signup', 'account',
    'billing', 'payments', 'assets', 'files', 'uptime', 'alerts',
    'notifications', 'webhook', 'jobs', 'careers', 'about', 'team',
    'contact', 'legal', 'privacy', 'terms', 'partners', 'customers',
    'clients', 'vendors', 'suppliers', 'app', 'apps', 'application',
    'staging', 'production', 'prod', 'sandbox', 'testing', 'qa', 'uat',
    'internal', 'intranet', 'extranet', 'vpn2', 'remote2', 'citrix',
    'rdp', 'terminal', 'ssh2', 'sftp', 'git', 'gitlab', 'github',
    'jenkins', 'ci', 'cd', 'build', 'deploy', 'release', 'code',
    'repo', 'svn', 'bitbucket', 'jira', 'confluence', 'wiki2', 'kb',
    'knowledge', 'help2', 'helpdesk', 'ticket', 'tickets', 'support2',
    'crm', 'erp', 'hr', 'payroll', 'finance', 'accounting', 'sales',
    'marketing', 'design', 'research', 'data', 'bigdata', 'ml', 'ai',
    'reports', 'reporting', 'bi', 'warehouse', 'etl', 'pipeline',
    'kafka', 'rabbitmq', 'redis', 'elasticsearch', 'kibana', 'grafana',
    'prometheus', 'nagios', 'zabbix', 'splunk', 'logstash', 'elk',
    'docker', 'k8s', 'kubernetes', 'rancher', 'vault', 'consul',
    'traefik', 'nginx', 'apache', 'haproxy', 'lb', 'loadbalancer',
    'edge', 'waf', 'firewall', 'proxy2', 'gateway2', 'vpn3',
    'mfa', 'sso', 'oauth', 'saml', 'ldap', 'ad', 'directory',
    'mail3', 'smtp2', 'mxs', 'relay', 'bounce', 'mailer', 'newsletter',
    'smtp3', 'imap2', 'pop4', 'webmail2', 'roundcube', 'horde',
    'store', 'ecommerce', 'cart', 'checkout', 'order', 'orders',
    'product', 'products', 'catalog', 'inventory', 'warehouse2',
    'shipping', 'delivery', 'tracking', 'logistics', 'supply',
    'pay', 'payment', 'payments2', 'invoice', 'invoices', 'receipt',
    'subscription', 'plan', 'plans', 'pricing', 'quote', 'quotes',
    'social', 'community2', 'forum2', 'board', 'discuss', 'talk',
    'blog2', 'news2', 'press', 'media2', 'podcast', 'video2', 'stream',
    'live', 'broadcast', 'tv', 'radio', 'music', 'audio',
    'map', 'maps', 'geo', 'location', 'places', 'search',
    'mobile2', 'android', 'ios', 'app2', 'pwa', 'widget',
    'sdk', 'developer', 'dev2', 'developers', 'api2', 'api3',
    'rest', 'graphql', 'soap', 'wsdl', 'ws', 'websocket',
    'push', 'notify', 'sms', 'whatsapp', 'telegram', 'slack',
    'integration', 'webhook2', 'zapier', 'ifttt', 'connector',
    'old2', 'legacy', 'archive', 'backup2', 'recovery', 'dr',
    'failover', 'ha', 'cluster', 'node', 'node2', 'worker',
    'master', 'slave', 'replica', 'primary', 'secondary',
    'us', 'eu', 'asia', 'uk', 'de', 'fr', 'jp', 'au', 'ca', 'sg',
    'us-east', 'us-west', 'eu-west', 'ap-south', 'global',
]


def normalize_domain(url: str) -> str:
    parsed = urlparse(url)
    domain = parsed.hostname
    if not domain:
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    domain = domain.split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def resolve_with_retry(hostname: str, retries: int = 2) -> str:
    for _ in range(retries):
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            time.sleep(0.1)
    return None


def run_subfinder(domain: str) -> List[str]:
    possible_paths = [
        f"{GO_PATH}/subfinder",
        "/usr/local/bin/subfinder",
        "/usr/bin/subfinder",
        os.path.expanduser("~/go/bin/subfinder"),
    ]
    subfinder_path = next((p for p in possible_paths if os.path.exists(p) and os.access(p, os.X_OK)), None)

    if not subfinder_path:
        print("[Subfinder] Not found — skipping")
        return []

    try:
        print(f"[Subfinder] Using: {subfinder_path}")
        result = subprocess.run(
            [subfinder_path, '-d', domain, '-silent', '-timeout', '30'],
            capture_output=True, text=True, timeout=60,
        )
        lines = [l.strip() for l in result.stdout.split('\n') if l.strip()]
        print(f"[Subfinder] Found: {len(lines)}")
        return lines
    except subprocess.TimeoutExpired:
        print("[Subfinder] Timeout")
        return []
    except Exception as e:
        print(f"[Subfinder] Error: {e}")
        return []


def run_assetfinder(domain: str) -> List[str]:
    possible_paths = [
        "/usr/bin/assetfinder",
        "/usr/local/bin/assetfinder",
        os.path.expanduser("~/go/bin/assetfinder"),
    ]
    assetfinder_path = next((p for p in possible_paths if os.path.exists(p) and os.access(p, os.X_OK)), None)

    if not assetfinder_path:
        print("[Assetfinder] Not found — skipping")
        return []

    try:
        print(f"[Assetfinder] Using: {assetfinder_path}")
        result = subprocess.run(
            [assetfinder_path, '--subs-only', domain],
            capture_output=True, text=True, timeout=45,
        )
        lines = [l.strip() for l in result.stdout.split('\n') if l.strip()]
        print(f"[Assetfinder] Found: {len(lines)}")
        return lines
    except subprocess.TimeoutExpired:
        print("[Assetfinder] Timeout")
        return []
    except Exception as e:
        print(f"[Assetfinder] Error: {e}")
        return []


def dns_bruteforce(domain: str) -> List[str]:
    found = []
    print(f"[DNS Bruteforce] Trying {len(BRUTE_SUBDOMAINS)} subdomains...")
    for sub in BRUTE_SUBDOMAINS:
        target = f"{sub}.{domain}"
        ip = resolve_with_retry(target)
        if ip:
            found.append(target)
            print(f"[DNS Bruteforce] Found: {target} -> {ip}")
    print(f"[DNS Bruteforce] Total: {len(found)}")
    return found


def discover_subdomains(url: str) -> dict:
    domain = normalize_domain(url)
    print(f"\n{'='*50}")
    print(f"[Subdomain Discovery] Target: {domain}")
    print(f"{'='*50}")

    all_subdomains: set = set()

    # 1. Subfinder
    all_subdomains.update(run_subfinder(domain))

    # 2. Assetfinder
    all_subdomains.update(run_assetfinder(domain))

    # 3. DNS Bruteforce
    all_subdomains.update(dns_bruteforce(domain))

    all_subdomains = sorted(all_subdomains)
    print(f"{'='*50}")
    print(f"[TOTAL] Unique subdomains: {len(all_subdomains)}")
    print(f"{'='*50}")

    results = []
    for sub in all_subdomains:
        ip = resolve_with_retry(sub)
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