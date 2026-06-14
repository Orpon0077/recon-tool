import re
import requests
from playwright.sync_api import sync_playwright

def scan_javascript(url: str) -> dict:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            
            # Get all JavaScript URLs
            js_urls = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(src => src && src.length > 0);
            }""")
            
            browser.close()
        
        collected_data = {
            "total_js_files": len(js_urls),
            "js_files": [{"url": u} for u in js_urls[:20]],
            "api_endpoints": [],
            "emails": [],
            "tokens": [],
            "internal_paths": [],
            "social_media": []
        }
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        for js_url in js_urls[:20]:
            try:
                response = requests.get(js_url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                content = response.text
                
                # Find emails
                emails = re.findall(email_pattern, content, re.IGNORECASE)
                for email in emails:
                    if email not in collected_data["emails"]:
                        collected_data["emails"].append(email)
                
                # Find API endpoints
                api_pattern = r'["\'](/api/[^\s"\']+)["\']'
                apis = re.findall(api_pattern, content)
                for api in apis:
                    if api not in collected_data["api_endpoints"]:
                        collected_data["api_endpoints"].append(api)
                
            except Exception:
                pass
        
        collected_data["emails"] = list(set(collected_data["emails"]))[:10]
        collected_data["api_endpoints"] = list(set(collected_data["api_endpoints"]))[:20]
        
        return collected_data
        
    except Exception as e:
        return {"error": str(e), "total_js_files": 0}
