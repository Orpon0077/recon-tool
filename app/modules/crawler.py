import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import CrawlResult, EndpointInfo
from app.modules.playwright_manager import playwright_manager

def crawl_website(url: str) -> CrawlResult:
    """Crawl website - tries Playwright first, then requests"""
    try:
        endpoints = []
        seen = set()
        html_content = None
        
        # Method 1: Playwright (for JS-rendered sites) - using shared manager
        try:
            import asyncio
            
            async def _crawl():
                page = await playwright_manager.new_page()
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(2000)
                    content = await page.content()
                    await page.close()
                    return content
                except Exception as e:
                    await page.close()
                    raise e
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            html_content = loop.run_until_complete(_crawl())
            loop.close()
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
