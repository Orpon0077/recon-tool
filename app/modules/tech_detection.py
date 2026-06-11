import re
import requests
from app.models import TechDetectionResult

def detect_technologies(url: str):
    from playwright.sync_api import sync_playwright
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=45000)
            html = page.content()
            
            response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            browser.close()
        
        technologies = {}
        
        # JavaScript Framework - আলাদা আলাদা করে
        js_frameworks = []
        
        if re.search(r'react|__react|data-react', html, re.IGNORECASE):
            js_frameworks.append("React")
        
        if re.search(r'_next/static|__next|next/dist', html, re.IGNORECASE):
            js_frameworks.append("Next.js")
        
        if js_frameworks:
            technologies["JavaScript Framework"] = js_frameworks
        
        # CDN
        if 'x-amz-cf-id' in headers:
            technologies["CDN"] = ["AWS CloudFront"]
        elif 'cf-ray' in headers:
            technologies["CDN"] = ["Cloudflare"]
        
        # Hosting
        if 'x-amzn-requestid' in headers:
            technologies["Hosting"] = ["AWS"]
        
        # Protocol
        if 'alt-svc' in headers and 'h3' in headers['alt-svc']:
            technologies["Protocol"] = ["HTTP/3"]
        
        # Backend
        if 'x-powered-by' in headers:
            powered = headers['x-powered-by']
            if 'next' in powered.lower():
                technologies["Backend"] = ["Next.js"]
            elif 'node' in powered.lower():
                technologies["Backend"] = ["Node.js"]
        
        total = sum(len(v) for v in technologies.values())
        
        return TechDetectionResult(
            url=url,
            technologies=technologies,
            total_found=total,
        )
        
    except Exception as e:
        return TechDetectionResult(url=url, error=str(e))
