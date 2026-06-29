import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_javascript(url: str) -> dict:
    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        
        # ── Extract JS files ──
        js_urls = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            full_url = urljoin(url, src)
            js_urls.append(full_url)
        
        # ── Also check preload links ──
        for link in soup.find_all("link", rel=["preload", "modulepreload"]):
            if link.get("as") == "script" and link.get("href"):
                full_url = urljoin(url, link["href"])
                if full_url not in js_urls:
                    js_urls.append(full_url)
        
        print(f"[JS Scanner] Found {len(js_urls)} JS files")
        
        # ── Prepare data with file names ──
        js_files = []
        for u in js_urls[:10]:
            js_files.append({
                "url": u,
                "name": u.split('/')[-1] if '/' in u else u
            })
        
        collected = {
            "total_js_files": len(js_urls),
            "js_files": js_files,
            "emails": [],
            "internal_paths": []
        }
        
        # ── Extract emails from JS files ──
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        for js_url in js_urls[:10]:
            try:
                content = requests.get(js_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"}).text[:100000]
                emails = re.findall(email_pattern, content, re.IGNORECASE)
                for email in emails:
                    if email not in collected["emails"]:
                        collected["emails"].append(email)
            except:
                continue
        
        collected["emails"] = list(set(collected["emails"]))[:10]
        
        print(f"[JS Scanner] ✅ {len(js_urls)} files, {len(collected['emails'])} emails")
        return collected
        
    except Exception as e:
        print(f"[JS Scanner] ❌ Error: {e}")
        return {"error": str(e), "total_js_files": 0}
