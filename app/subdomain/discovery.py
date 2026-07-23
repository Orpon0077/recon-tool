"""
Subdomain Discovery Module
Uses Subfinder, Assetfinder, and socket fallback.
Resolves IPs, probes HTTP, detects technologies, flags sensitive names,
and classifies each subdomain as Live / Dead / Zombie.
"""

import logging
import subprocess
import socket
import re
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ── Check if dnspython is available ──
try:
    import dns.resolver
    DNS_AVAILABLE = True
except (ImportError, AttributeError):
    DNS_AVAILABLE = False
    logger.warning("dnspython not available. CNAME lookup and zombie detection will be skipped.")

# ── Zombie / takeover patterns ──
TAKEOVER_PATTERNS = {
    "github.io": "GitHub Pages",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "azurewebsites.net": "Azure Web Apps",
    "cloudfront.net": "AWS CloudFront",
    "herokuapp.com": "Heroku",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "firebaseapp.com": "Firebase Hosting",
    "readthedocs.io": "Read the Docs",
    "pages.dev": "Cloudflare Pages",
    "surge.sh": "Surge",
    "gitlab.io": "GitLab Pages",
    "bitbucket.io": "Bitbucket Pages",
    "000webhostapp.com": "000webhost",
    "x10.mx": "x10hosting",
    "zendesk.com": "Zendesk",
    "helpjuice.com": "Helpjuice",
    "tawk.to": "Tawk.to",
    "crisp.chat": "Crisp.chat",
}

SENSITIVE_PATTERNS = [
    "api", "admin", "backup", "demo", "staging", "db-", "-db",
    "portal", "dashboard", "dev", "test", "internal", "private",
]

TECH_SIGNATURES = {
    "Next.js": {"headers": ["x-powered-by"], "body": ["__NEXT_DATA__", "next/dist"]},
    "React": {"headers": [], "body": ["react", "react-dom"]},
    "Express": {"headers": ["x-powered-by"], "body": []},
    "Nginx": {"headers": ["server"], "body": []},
    "Apache": {"headers": ["server"], "body": []},
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": []},
    "Amazon CloudFront": {"headers": ["x-amz-cf-id", "x-amz-cf-pop"], "body": []},
    "WordPress": {"headers": [], "body": ["wp-content", "wp-includes"]},
    "Drupal": {"headers": [], "body": ["drupal", "sites/default"]},
    "Joomla": {"headers": [], "body": ["joomla", "media/system"]},
}


def extract_domain(target: str) -> str:
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        domain = parsed.netloc
    else:
        domain = target
    domain = domain.split(":")[0].strip("/")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def is_sensitive_subdomain(hostname: str) -> bool:
    host = hostname.lower()
    return any(pattern in host for pattern in SENSITIVE_PATTERNS)


def resolve_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return "N/A"


def get_cname(hostname: str) -> Optional[str]:
    """Return CNAME target, or None if dnspython is not available or lookup fails."""
    if not DNS_AVAILABLE:
        return None
    try:
        answers = dns.resolver.resolve(hostname, "CNAME", raise_on_no_answer=False)
        if answers:
            return str(answers[0].target).rstrip('.')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    return None


def detect_takeover(cname: str) -> Optional[str]:
    """Check if a CNAME points to a takeover‑vulnerable service."""
    if not cname:
        return None
    cname_lower = cname.lower()
    for pattern, service in TAKEOVER_PATTERNS.items():
        if pattern in cname_lower:
            return service
    return None


def detect_technologies_from_response(headers: dict, body: str = "") -> List[str]:
    detected = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for tech, sig in TECH_SIGNATURES.items():
        for h in sig.get("headers", []):
            if h in headers_lower:
                detected.add(tech)
                break
        if body:
            for pattern in sig.get("body", []):
                if pattern in body:
                    detected.add(tech)
                    break

    server = headers_lower.get("server", "")
    if server:
        if "cloudflare" in server.lower():
            detected.add("Cloudflare")
        elif "nginx" in server.lower():
            detected.add("Nginx")
        elif "apache" in server.lower():
            detected.add("Apache")
        elif "express" in server.lower():
            detected.add("Express")
    return sorted(detected)


def is_valid_subdomain(hostname: str, base_domain: str) -> tuple:
    """
    Check if a subdomain is valid and doesn't contain external domains.
    Returns (is_valid, possible_parsing_error, reason)
    
    Fix for Issue #2: Detects malformed entries like kulvdi.tru-connect.biz.axiler.com
    """
    # Check if it ends with the base domain
    if not hostname.endswith(base_domain):
        return False, True, f"Does not end with base domain: {base_domain}"
    
    # Remove base domain to check the prefix
    prefix = hostname[:-len(base_domain)].rstrip('.')
    
    # Check if the prefix contains what looks like another domain (has a dot with TLD pattern)
    # This detects "tru-connect.biz" inside "kulvdi.tru-connect.biz.axiler.com"
    if '.' in prefix:
        # Check if prefix contains common TLD patterns
        tld_pattern = r'\.(com|org|net|biz|info|io|co|uk|us|de|fr|jp|cn|in|au|ca|ru|br|mx|it|nl|es|se|no|pl|tr|za|kr|tw|be|at|ch|dk|fi|ie|pt|gr|il|ae|sa|ng|pk|my|vn|th|ph|id|hk|nz|cl|ar|pe|ve|co\.uk|co\.in|com\.au)'
        if re.search(tld_pattern, prefix, re.IGNORECASE):
            return False, True, f"Contains external domain pattern in prefix: {prefix}"
    
    return True, False, "Valid"


def is_nextjs_internal_string(text: str) -> bool:
    """
    Check if a string is a Next.js internal framework string that should be filtered out.
    Fix for Issue #3: Denylist for false positives.
    """
    nextjs_patterns = [
        r'__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE',
        r'__NEXT_DATA__',
        r'next/dist',
        r'--next-',
        r'home-integrations__track--reverse',
        r'__NEXT_',
        r'__next_',
        r'__webpack_',
        r'__REACT_',
        r'__DEV__',
        r'__PROD__',
        r'__BROWSER__',
        r'__SERVER__',
        r'__NEXT_',
        r'next/',
        r'next-',
    ]
    for pattern in nextjs_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def probe_subdomain(hostname: str, timeout: int = 5, source: str = "dns_bruteforce") -> Dict[str, Any]:
    """
    Probe a subdomain: resolve IP, check CNAME, detect takeover, HTTP probe.
    Returns dict with all fields, including 'status' and 'resolved'.
    """
    ip = resolve_ip(hostname)
    cname = get_cname(hostname)
    takeover_service = detect_takeover(cname)

    # Fix for Issue #1: resolved field is already here
    resolved = (ip != "N/A")
    if resolved:
        status = "live"
    elif takeover_service:
        status = "zombie"
    else:
        status = "dead"

    result = {
        "subdomain": hostname,
        "ip": ip,
        "cname": cname,
        "takeover_service": takeover_service,
        "status": status,
        "resolved": resolved,          # ← Fix #1: Resolved flag
        "source": source,             # ← Source tracking
        "http_status": "N/A",
        "technologies": [],
        "open_ports": [],
        "screenshot": None,
        "sensitive": is_sensitive_subdomain(hostname),
        "possible_parsing_error": False,  # ← Fix #2: will be set by caller if needed
    }

    # HTTP probe only for live subdomains
    if status == "live":
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{hostname}",
                    timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "RECON-Dashboard/1.0"},
                )
                result["http_status"] = resp.status_code
                body_snippet = resp.text[:2000]
                result["technologies"] = detect_technologies_from_response(
                    resp.headers, body_snippet
                )
                break
            except requests.RequestException:
                continue

    return result


def merge_subdomain_lists(*sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for source in sources:
        for entry in source:
            if isinstance(entry, str):
                entry = {"subdomain": entry, "ip": "N/A"}
            hostname = entry.get("subdomain") or entry.get("name")
            if not hostname:
                continue
            existing = merged.get(hostname, {})
            merged[hostname] = {
                "subdomain": hostname,
                "ip": entry.get("ip") or existing.get("ip") or resolve_ip(hostname),
                "cname": entry.get("cname") or existing.get("cname"),
                "takeover_service": entry.get("takeover_service") or existing.get("takeover_service"),
                "status": entry.get("status") or existing.get("status") or "dead",
                "resolved": entry.get("resolved", existing.get("resolved", False)),
                "source": entry.get("source") or existing.get("source") or "unknown",
                "http_status": entry.get("http_status", existing.get("http_status")),
                "technologies": existing.get("technologies", []) or entry.get("technologies", []),
                "open_ports": existing.get("open_ports", []) or entry.get("open_ports", []),
                "screenshot": existing.get("screenshot") or entry.get("screenshot"),
                "sensitive": entry.get("sensitive", existing.get("sensitive", is_sensitive_subdomain(hostname))),
                "possible_parsing_error": entry.get("possible_parsing_error", existing.get("possible_parsing_error", False)),
            }
    return sorted(merged.values(), key=lambda item: item["subdomain"])


def discover_subdomains(target: str, extra_subdomains: List[str] | None = None) -> Dict[str, Any]:
    """
    Discover subdomains using external tools + socket fallback.
    Returns all subdomains with classification: live, dead, zombie.
    """
    domain = extract_domain(target)
    logger.info(f"Subdomain Discovery for {domain}")

    subdomains: Set[str] = set(extra_subdomains or [])

    # Subfinder
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            found = [s.strip() for s in result.stdout.splitlines() if s.strip()]
            subdomains.update(found)
            logger.info(f"Subfinder found: {len(found)}")
    except subprocess.TimeoutExpired:
        logger.warning(f"Subfinder timed out for {domain}")
    except Exception as e:
        logger.warning(f"Subfinder failed: {e}")

    # Assetfinder
    try:
        result = subprocess.run(
            ["assetfinder", domain],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode == 0:
            found = [
                s.strip()
                for s in result.stdout.splitlines()
                if s.strip() and s.strip().endswith(domain)
            ]
            subdomains.update(found)
            logger.info(f"Assetfinder found: {len(found)}")
    except subprocess.TimeoutExpired:
        logger.warning(f"Assetfinder timed out for {domain}")
    except Exception as e:
        logger.warning(f"Assetfinder failed: {e}")

    # Socket fallback
    common = [
        "www", "mail", "ftp", "blog", "dev", "test", "api", "admin",
        "cdn", "static", "media", "app", "portal", "auth", "staging", "demo",
    ]
    for sub in common:
        full = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full)
            subdomains.add(full)
        except socket.error:
            pass

    # ── Fix #2: Validate each subdomain and filter malformed entries ──
    valid_subdomains = set()
    for s in subdomains:
        is_valid, is_parsing_error, reason = is_valid_subdomain(s, domain)
        if is_valid:
            valid_subdomains.add(s)
        else:
            if is_parsing_error:
                logger.warning(f"Malformed subdomain detected (possible parsing error): {s} - {reason}")
            else:
                logger.debug(f"Skipping subdomain: {s} - {reason}")
    
    # Also filter by base domain ending (safety net)
    subdomains = {s for s in valid_subdomains if s.endswith(domain)}
    
    # Probe each subdomain
    result_list: List[Dict[str, Any]] = []
    for hostname in sorted(subdomains):
        probe_result = probe_subdomain(hostname, timeout=4, source="dns_bruteforce")
        # Re-check validity for the specific hostname
        is_valid, is_parsing_error, _ = is_valid_subdomain(hostname, domain)
        if is_parsing_error:
            probe_result["possible_parsing_error"] = True
            logger.warning(f"Marked as possible parsing error: {hostname}")
        result_list.append(probe_result)

    # Summary counts
    live_count = sum(1 for s in result_list if s.get("status") == "live")
    dead_count = sum(1 for s in result_list if s.get("status") == "dead")
    zombie_count = sum(1 for s in result_list if s.get("status") == "zombie")
    sensitive_count = sum(1 for s in result_list if s.get("sensitive"))
    parsing_errors = sum(1 for s in result_list if s.get("possible_parsing_error", False))

    logger.info(f"Total: {len(result_list)} | Live: {live_count} | Dead: {dead_count} | Zombie: {zombie_count} | Parsing Errors: {parsing_errors}")

    return {
        "subdomains": result_list,
        "total_found": len(result_list),
        "live_count": live_count,
        "dead_count": dead_count,
        "zombie_count": zombie_count,
        "sensitive_count": sensitive_count,
        "parsing_error_count": parsing_errors,
    }