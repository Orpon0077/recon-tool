import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import CrawlResult, EndpointInfo

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def crawl_website(url: str) -> CrawlResult:
    try:
        url = normalize_url(url)
        endpoints = []
        seen = set()
        
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
        soup = BeautifulSoup(response.text, "html.parser")
        
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            if href and not href.startswith(("#", "mailto:", "tel:", "javascript:")):
                full_url = urljoin(url, href)
                clean_url = full_url.split('?')[0].split('#')[0]
                if clean_url not in seen and len(endpoints) < 100:
                    seen.add(clean_url)
                    endpoints.append(
                        EndpointInfo(
                            url=clean_url,
                            method="GET",
                            status_code=200,
                            content_type="text/html"
                        )
                    )
        
        return CrawlResult(url=url, endpoints=endpoints, total_found=len(endpoints))
    except Exception as e:
        return CrawlResult(url=url, error=str(e))