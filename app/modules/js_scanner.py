import re
import requests
from playwright.sync_api import sync_playwright

def scan_javascript(url: str) -> dict:
    """JavaScript Scanner - Extracts emails and paths"""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(3000)
            
            js_urls = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(src => src && src.includes('.js'));
            }""")
            
            browser.close()
        
        print(f"[JS Scanner] Found {len(js_urls)} JS files")
        
        collected_data = {
            "total_js_files": len(js_urls),
            "js_files": [{"url": u} for u in js_urls[:10]],
            "api_endpoints": [],
            "emails": [],
            "tokens": [],
            "internal_paths": [],
            "social_media": []
        }
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        path_pattern = r'["\'](/(?:[a-zA-Z0-9_\-]+/?)+)["\']'
        
        # Scan first 10 JS files
        for js_url in js_urls[:10]:
            try:
                response = requests.get(js_url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                content = response.text[:100000]  # 100KB
                
                # Emails
                emails = re.findall(email_pattern, content, re.IGNORECASE)
                for email in emails:
                    if email not in collected_data["emails"]:
                        collected_data["emails"].append(email)
                
                # Paths
                paths = re.findall(path_pattern, content)
                for path in paths:
                    if len(path) > 3 and path not in collected_data["internal_paths"]:
                        if not path.startswith(('/_', '/static', '/assets', '/css', '/js')):
                            collected_data["internal_paths"].append(path)
                
            except Exception as e:
                print(f"[JS Scanner] Error scanning {js_url}: {e}")
                pass
        
        collected_data["emails"] = list(set(collected_data["emails"]))[:10]
        collected_data["internal_paths"] = list(set(collected_data["internal_paths"]))[:20]
        
        print(f"[JS Scanner] Found {len(collected_data['emails'])} emails, {len(collected_data['internal_paths'])} paths")
        
        return collected_data
        
    except Exception as e:
        print(f"[JS Scanner] Fatal error: {e}")
        return {"error": str(e), "total_js_files": 0}
