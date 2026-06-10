# ── Crawler Module (Improved) ─────────────────────────────

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import CrawlResult, EndpointInfo

def get_domain_root(netloc: str) -> str:
    """Extract root domain (remove www, subdomain)"""
    parts = netloc.lower().split('.')
    if len(parts) >= 2:
        # Remove www and subdomains, keep main domain
        return '.'.join(parts[-2:])
    return netloc

def is_same_domain(url_netloc: str, base_netloc: str) -> bool:
    """Check if two domains are the same (handles www vs non-www)"""
    root1 = get_domain_root(url_netloc)
    root2 =get_domain_root(base_netloc)
    return root1 == root2

def get_all_links(html: str, base_url: str) -> set[str]:
    """
    HTML থেকে সব links বের করে।
    Relative links কে absolute এ convert করে।
    """
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    
    base_domain = urlparse(base_url).netloc

    # Also try to find links from JavaScript (basic)
    script_content = ""
    for script in soup.find_all("script"):
        if script.string:
            script_content += script.string
    
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()

        # Skip empty and special links
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue

        # Convert relative to absolute URL
        absolute_url = urljoin(base_url, href)
        parsed_url = urlparse(absolute_url)
        
        # Skip empty netloc
        if not parsed_url.netloc:
            continue
            
        clean_url = parsed_url._replace(fragment="").geturl()

        # Check if same domain (more flexible)
        if is_same_domain(parsed_url.netloc, base_domain):
            links.add(clean_url)
    
    # Also add any URLs found in JavaScript
    import re
    js_urls = re.findall(r'https?://[^\s"\'<>]+', script_content)
    for js_url in js_urls:
        parsed = urlparse(js_url)
        if parsed.netloc and is_same_domain(parsed.netloc, base_domain):
            links.add(js_url)

    return links

def check_endpoint(url: str) -> EndpointInfo:
    """Check a single endpoint"""
    try:
        response = requests.get(
            url, 
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )

        content_type = response.headers.get("Content-Type", "").split(";")[0].strip()

        return EndpointInfo(
            url=url,
            status_code=response.status_code,
            method="GET",
            content_type=content_type,
        )

    except Exception:
        return EndpointInfo(
            url=url,
            status_code=None,
            method="GET",
            content_type=None,
        )

def crawl_website(url: str) -> CrawlResult:
    """Crawl website and find all endpoints"""
    try:
        print(f"[Crawler] Starting crawl for: {url}")
        
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )
        
        print(f"[Crawler] HTTP {response.status_code}")

        # Get all links
        links = get_all_links(response.text, url)
        print(f"[Crawler] Found {len(links)} unique links")

        # Add main URL
        links.add(url)

        # Check up to 50 endpoints
        links_to_check = list(links)[:50]

        endpoints = []
        for i, link in enumerate(links_to_check):
            print(f"[Crawler] Checking {i+1}/{len(links_to_check)}: {link[:50]}...")
            endpoint_info = check_endpoint(link)
            endpoints.append(endpoint_info)

        # Sort by status code
        endpoints.sort(key=lambda x: x.status_code or 999)

        print(f"[Crawler] Done! Total: {len(endpoints)} endpoints")

        return CrawlResult(
            url=url,
            endpoints=endpoints,
            total_found=len(endpoints),
        )

    except requests.exceptions.ConnectionError:
        return CrawlResult(url=url, error="Connection failed")
    except requests.exceptions.Timeout:
        return CrawlResult(url=url, error="Request timed out")
    except requests.exceptions.RequestException as e:
        return CrawlResult(url=url, error=str(e))