import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import CrawlResult, EndpointInfo
import time
import re

def crawl_website(url: str) -> CrawlResult:
    """Crawl website - Playwright first, Requests fallback"""
    try:
        endpoints = []
        seen = set()
        start_time = time.time()
        html_content = None
        
        print(f"[Crawler] Starting crawl for {url}")
        
        # ── Method 1: Playwright (JS-rendered) ──
        try:
            from playwright.sync_api import sync_playwright
            
            print("[Crawler] Trying Playwright (JS-rendered)...")
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-dev-shm-usage']
                )
                page = browser.new_page()
                
                # Longer timeout for JS sites
                page.set_default_timeout(60000)
                page.goto(url, wait_until="networkidle", timeout=60000)
                page.wait_for_timeout(3000)
                
                # Get page content after JS execution
                html_content = page.content()
                browser.close()
                print("[Crawler] ✅ Playwright succeeded")
        except Exception as e:
            print(f"[Crawler] Playwright failed: {e}")
        
        # ── Method 2: Requests (fallback) ──
        if not html_content:
            try:
                print("[Crawler] Trying Requests (static)...")
                response = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    headers=REQUEST_HEADERS,
                    allow_redirects=True,
                )
                html_content = response.text
                print("[Crawler] ✅ Requests succeeded")
            except Exception as e:
                print(f"[Crawler] Requests failed: {e}")
                return CrawlResult(url=url, error=f"Crawl failed: {str(e)[:100]}")
        
        # ── Parse HTML ──
        if html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            
            # Find all links from anchor tags
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    full_url = urljoin(url, href)
                    clean_url = full_url.split('?')[0].split('#')[0]
                    
                    if clean_url not in seen and len(endpoints) < 100:
                        seen.add(clean_url)
                        endpoints.append(EndpointInfo(
                            url=clean_url,
                            method="GET",
                            status_code=200,
                            content_type="text/html"
                        ))
            
            # ── Also find links from JavaScript ──
            script_content = ""
            for script in soup.find_all("script"):
                if script.string:
                    script_content += script.string
            
            # Find URLs in JS
            js_links = re.findall(r'https?://[^\s"\'<>]+', script_content)
            for js_link in js_links:
                # Check if same domain
                parsed_js = urlparse(js_link)
                parsed_base = urlparse(url)
                if parsed_js.netloc == parsed_base.netloc:
                    clean_url = js_link.split('?')[0].split('#')[0]
                    if clean_url not in seen and len(endpoints) < 100:
                        seen.add(clean_url)
                        endpoints.append(EndpointInfo(
                            url=clean_url,
                            method="GET",
                            status_code=200,
                            content_type="text/html"
                        ))
        
        elapsed = time.time() - start_time
        print(f"[Crawler] ✅ Found {len(endpoints)} endpoints in {elapsed:.1f}s")
        
        return CrawlResult(
            url=url,
            endpoints=endpoints,
            total_found=len(endpoints),
        )
        
    except Exception as e:
        print(f"[Crawler] Error: {e}")
        return CrawlResult(url=url, error=f"Crawl error: {str(e)[:100]}")
