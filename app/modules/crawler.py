import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import CrawlResult, EndpointInfo

def crawl_website(url: str) -> CrawlResult:
    try:
        response = requests.get(url, timeout=15, headers=REQUEST_HEADERS)
        soup = BeautifulSoup(response.text, "html.parser")
        
        endpoints = []
        seen = set()
        
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                full_url = urljoin(url, href)
                # Remove query parameters for cleaner list
                clean_url = full_url.split('?')[0]
                
                if clean_url not in seen and len(endpoints) < 30:
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
        return CrawlResult(url=url, error=str(e))
