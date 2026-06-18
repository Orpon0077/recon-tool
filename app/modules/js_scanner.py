import re
import requests
from playwright.sync_api import sync_playwright

def scan_javascript(url: str) -> dict:
    """JS Scanner - Enhanced pattern matching"""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(3000)
            
            js_urls = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(src => src && (src.includes('.js') || src.includes('.mjs')));
            }""")
            
            browser.close()
        
        collected_data = {
            "total_js_files": len(js_urls),
            "js_files": [{"url": u} for u in js_urls[:10]],
            "api_endpoints": [],
            "emails": [],
            "tokens": [],
            "internal_paths": [],
            "social_media": []
        }
        
        # Enhanced patterns
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        api_pattern = r'["\'](/api/[^\s"\']+)["\']'
        path_pattern = r'["\'](/(?:[a-zA-Z0-9_\-]+/?)+)["\']'
        token_pattern = r'(?:api[_-]?key|token|secret|access[_-]?token)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']'
        
        social_patterns = {
            'facebook': r'facebook\.com/([a-zA-Z0-9.]+)',
            'twitter': r'twitter\.com/([a-zA-Z0-9_]+)',
            'linkedin': r'linkedin\.com/(?:company|in)/([a-zA-Z0-9_-]+)',
            'instagram': r'instagram\.com/([a-zA-Z0-9_.]+)',
            'github': r'github\.com/([a-zA-Z0-9_-]+)',
        }
        
        # Scan 10 JS files
        for js_url in js_urls[:10]:
            try:
                response = requests.get(js_url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                content = response.text[:100000]
                
                # Emails
                emails = re.findall(email_pattern, content, re.IGNORECASE)
                for email in emails:
                    if email not in collected_data["emails"]:
                        collected_data["emails"].append(email)
                
                # API endpoints
                apis = re.findall(api_pattern, content)
                for api in apis:
                    if api not in collected_data["api_endpoints"]:
                        collected_data["api_endpoints"].append(api)
                
                # Internal paths
                paths = re.findall(path_pattern, content)
                for path in paths:
                    if len(path) > 3 and path not in collected_data["internal_paths"]:
                        if not path.startswith(('/_', '/static', '/assets', '/css', '/js')):
                            collected_data["internal_paths"].append(path)
                
                # Tokens/Keys
                tokens = re.findall(token_pattern, content, re.IGNORECASE)
                for token in tokens:
                    if token not in collected_data["tokens"]:
                        collected_data["tokens"].append(token)
                
                # Social Media
                for platform, pattern in social_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        display = f"{platform}: {match}"
                        if display not in collected_data["social_media"]:
                            collected_data["social_media"].append(display)
                
            except:
                pass
        
        collected_data["emails"] = list(set(collected_data["emails"]))[:10]
        collected_data["api_endpoints"] = list(set(collected_data["api_endpoints"]))[:15]
        collected_data["internal_paths"] = list(set(collected_data["internal_paths"]))[:20]
        collected_data["tokens"] = list(set(collected_data["tokens"]))[:5]
        collected_data["social_media"] = list(set(collected_data["social_media"]))[:5]
        
        print(f"[JS Scanner] {len(js_urls)} JS files, {len(collected_data['emails'])} emails, {len(collected_data['internal_paths'])} paths")
        
        return collected_data
        
    except Exception as e:
        print(f"[JS Scanner] Error: {e}")
        return {"error": str(e), "total_js_files": 0}