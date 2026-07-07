# Crawler / Endpoint Discovery Module
# Uses Playwright + Requests, plus optional smart common-path probe
# Only includes endpoints with status 200-399

import asyncio
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}
MAX_ENDPOINTS = 150
REQUEST_TIMEOUT = 8

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

    # onclick attributes
    for tag in soup.find_all(attrs={"onclick": True}):
        onclick = tag["onclick"]
        urls = re.findall(r"['\"]([/][^'\"]+)['\"]", onclick)
        for u in urls:
            absolute_url = urljoin(base_url, u)
            parsed = urlparse(absolute_url)
            if parsed.netloc == base_domain:
                links.add(absolute_url)

    # SPA routes in script tags
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


def probe_common_paths(base_url: str) -> set:
    """Check common paths and return those that return 200-399."""
    found = set()
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        try:
            resp = requests.get(url, timeout=5, headers=REQUEST_HEADERS, allow_redirects=True, verify=False)
            if 200 <= resp.status_code < 400:
                found.add(url)
                print(f"[Crawler] Common path found: {url} ({resp.status_code})")
        except Exception:
            pass
    return found


async def get_html_playwright(url: str) -> str:
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
            )
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
            await page.wait_for_timeout(3000)
            html = await page.content()
            await browser.close()
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


async def crawl_website(url: str) -> dict:
    print(f"[Crawler] Starting crawl: {url}")

    all_links = set()
    all_links.add(url)

    # 1. Playwright
    playwright_html = await get_html_playwright(url)
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
    if len(all_links) < 10:
        print("[Crawler] Few links found, probing common paths...")
        common_links = probe_common_paths(url)
        all_links.update(common_links)

    # Cap at MAX_ENDPOINTS
    links_to_check = list(all_links)[:MAX_ENDPOINTS]
    print(f"[Crawler] Checking {len(links_to_check)} endpoints...")

    endpoints = []
    for link in links_to_check:
        info = check_endpoint(link)
        if info and 200 <= info["status_code"] < 400:
            endpoints.append(info)

    endpoints.sort(key=lambda x: x.get("status_code") or 999)

    print(f"[Crawler] Done. Valid endpoints: {len(endpoints)}")

    return {
        "url": url,
        "endpoints": endpoints,
        "total_found": len(endpoints),
    }