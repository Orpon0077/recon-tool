# Crawler / Endpoint Discovery Module
# Uses Playwright + Requests, plus optional smart common-path probe (parallel)
# Only includes endpoints with status 200-399
# Multi-threaded: Common path probing and endpoint checking run in parallel

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}
MAX_ENDPOINTS = 150
REQUEST_TIMEOUT = 120  # 2 minutes for individual HTTP requests

# Curated list of common web paths – only those likely to exist
COMMON_PATHS = [
    "/", "/about", "/contact", "/login", "/register", "/signup",
    "/admin", "/dashboard", "/profile", "/settings", "/search",
    "/blog", "/news", "/faq", "/help", "/support",
    "/api", "/api/v1", "/graphql", "/swagger", "/docs",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/privacy", "/terms", "/cookies",
]

def get_links_from_html(html: str, base_url: str) -> set:
    """Extract all internal links from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    base_domain = urlparse(base_url).netloc
    links = set()

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute_url = urljoin(base_url, href)
        parsed = urlparse(absolute_url)
        clean_url = parsed._replace(fragment="").geturl()
        if parsed.netloc == base_domain:
            links.add(clean_url)

    for tag in soup.find_all(attrs={"onclick": True}):
        onclick = tag["onclick"]
        urls = re.findall(r"['\"]([/][^'\"]+)['\"]", onclick)
        for u in urls:
            absolute_url = urljoin(base_url, u)
            parsed = urlparse(absolute_url)
            if parsed.netloc == base_domain:
                links.add(absolute_url)

    for script in soup.find_all("script"):
        if script.string:
            paths = re.findall(r'"(/[a-zA-Z0-9/_\-]+)"', script.string)
            for path in paths:
                if len(path) > 1 and "." not in path.split("/")[-1]:
                    absolute_url = urljoin(base_url, path)
                    parsed = urlparse(absolute_url)
                    if parsed.netloc == base_domain:
                        links.add(absolute_url)
    return links

def _probe_single_path(args: tuple) -> str:
    """Probe a single path (for thread pool execution)."""
    base_url, path = args
    url = urljoin(base_url, path)
    try:
        resp = requests.get(url, timeout=10, headers=REQUEST_HEADERS, allow_redirects=True, verify=False)
        if 200 <= resp.status_code < 400:
            print(f"[Crawler] Common path found: {url} ({resp.status_code})")
            return url
    except Exception:
        pass
    return None

def probe_common_paths(base_url: str) -> set:
    """Check common paths in parallel and return those that return 200-399.
    
    Uses ThreadPoolExecutor with 10 worker threads for parallel HTTP requests.
    """
    found = set()
    
    # Create args list for thread pool
    args_list = [(base_url, path) for path in COMMON_PATHS]
    
    # Use 10 threads to probe common paths in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_probe_single_path, args) for args in args_list]
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.add(result)
    
    return found

def get_html_playwright_sync(url: str) -> str:
    """Fetch HTML using Playwright (synchronous version)."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
            )
            page = context.new_page()
            # 180 seconds for page load
            page.goto(url, wait_until="domcontentloaded", timeout=180000)
            try:
                page.wait_for_load_state("networkidle", timeout=30000)
            except Exception:
                pass
            page.wait_for_timeout(5000)
            html = page.content()
            browser.close()
            return html
    except Exception as e:
        print(f"[Crawler] Playwright error: {e}")
        return ""

def get_html_requests(url: str) -> str:
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
            verify=False,
        )
        return response.text
    except Exception as e:
        print(f"[Crawler] Requests error: {e}")
        return ""

def check_endpoint(url: str) -> dict:
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
            verify=False,
        )
        content_type = response.headers.get("Content-Type", "").split(";")[0].strip()
        return {
            "url": url,
            "method": "GET",
            "status_code": response.status_code,
            "content_type": content_type,
        }
    except Exception:
        return None

def crawl_website(url: str) -> dict:
    """Synchronous crawl function – compatible with asyncio.to_thread.
    
    Uses multi-threading for:
    - Parallel common path probing (10 threads)
    - Parallel endpoint checking (20 threads)
    """
    print(f"[Crawler] Starting crawl: {url}")

    all_links = set()
    all_links.add(url)

    # 1. Playwright (sync)
    playwright_html = get_html_playwright_sync(url)
    if playwright_html:
        playwright_links = get_links_from_html(playwright_html, url)
        all_links.update(playwright_links)
        print(f"[Crawler] Playwright found {len(playwright_links)} links")

    # 2. Requests
    requests_html = get_html_requests(url)
    if requests_html:
        requests_links = get_links_from_html(requests_html, url)
        all_links.update(requests_links)
        print(f"[Crawler] Requests found {len(requests_links)} links")

    # 3. Smart common-path probe (only if we have few links, e.g., < 10)
    # Now uses ThreadPoolExecutor for parallel probing
    if len(all_links) < 10:
        print("[Crawler] Few links found, probing common paths (parallel with 10 threads)...")
        common_links = probe_common_paths(url)
        all_links.update(common_links)

    # Cap at MAX_ENDPOINTS
    links_to_check = list(all_links)[:MAX_ENDPOINTS]
    print(f"[Crawler] Checking {len(links_to_check)} endpoints (parallel with 20 threads)...")

    # Use ThreadPoolExecutor for parallel endpoint checking
    endpoints = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_endpoint, link) for link in links_to_check]
        for future in as_completed(futures):
            info = future.result()
            if info and 200 <= info["status_code"] < 400:
                endpoints.append(info)

    endpoints.sort(key=lambda x: x.get("status_code") or 999)

    print(f"[Crawler] Done. Valid endpoints: {len(endpoints)}")

    return {
        "url": url,
        "endpoints": endpoints,
        "total_found": len(endpoints),
    }