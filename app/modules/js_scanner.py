# ── JS Scanner Module (Pure Requests) ─────────────────────
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_javascript(url: str) -> dict:
    try:
        response = requests.get(url, timeout=10, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }, allow_redirects=True)
        
        soup = BeautifulSoup(response.text, "html.parser")
        
        js_urls = []
        for script in soup.find_all("script", src=True):
            full_url = urljoin(url, script["src"])
            if full_url not in js_urls:
                js_urls.append(full_url)
        
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
        api_pattern = r'["\'](/api/[^\s"\']+)["\']'
        path_pattern = r'["\'](/(?:[a-zA-Z0-9_\-]+/?)+)["\']'
        
        for js_url in js_urls[:10]:
            try:
                js_response = requests.get(js_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                content = js_response.text[:100000]
                
                emails = re.findall(email_pattern, content, re.IGNORECASE)
                for email in emails:
                    if email not in collected_data["emails"]:
                        collected_data["emails"].append(email)
                
                apis = re.findall(api_pattern, content)
                for api in apis:
                    if api not in collected_data["api_endpoints"]:
                        collected_data["api_endpoints"].append(api)
                
                paths = re.findall(path_pattern, content)
                for path in paths:
                    if len(path) > 3 and path not in collected_data["internal_paths"]:
                        if not path.startswith(('/_', '/static', '/assets', '/css', '/js')):
                            collected_data["internal_paths"].append(path)
            except:
                continue
        
        collected_data["emails"] = list(set(collected_data["emails"]))[:10]
        collected_data["api_endpoints"] = list(set(collected_data["api_endpoints"]))[:15]
        collected_data["internal_paths"] = list(set(collected_data["internal_paths"]))[:20]
        
        print(f"[JS Scanner] ✅ {len(js_urls)} JS files, {len(collected_data['emails'])} emails")
        return collected_data
        
    except Exception as e:
        print(f"[JS Scanner] ❌ Error: {e}")
        return {"error": str(e), "total_js_files": 0}
