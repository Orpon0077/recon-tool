import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import CrawlResult, EndpointInfo

def crawl_website(url: str) -> CrawlResult:
    """Crawl website - tries Playwright first, then requests"""
    try:
        endpoints = []
        seen = set()
        html_content = None
        
        # Method 1: Playwright (for JS-rendered sites)
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=20000)
                html_content = page.content()
                browser.close()
            print("[Crawler] Using Playwright (JS-rendered)")
        except Exception as e:
            print(f"[Crawler] Playwright failed: {e}")
        
        # Method 2: Requests (fallback)
        if not html_content:
            try:
                response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
                html_content = response.text
                print("[Crawler] Using Requests (static HTML)")
            except Exception as e:
                print(f"[Crawler] Requests failed: {e}")
                return CrawlResult(url=url, error=str(e))
        
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Find all links
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                full_url = urljoin(url, href)
                clean_url = full_url.split('?')[0]
                
                if clean_url not in seen and len(endpoints) < 50:
                    seen.add(clean_url)
                    endpoints.append(EndpointInfo(
                        url=clean_url,
                        method="GET",
                        status_code=200,
                        content_type="text/html"
                    ))
        
        return CrawlResult(
            url=url,
            endpoints=endpoints,
            total_found=len(endpoints),
        )
        
    except Exception as e:
        print(f"Crawl error: {e}")
        return CrawlResult(url=url, error=str(e))
