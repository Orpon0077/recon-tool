import requests
from bs4 import BeautifulSoup
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import TechDetectionResult

def detect_technologies(url: str) -> TechDetectionResult:
    try:
        technologies = {}
        
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text.lower()
        
        # ── Headers detection ──
        server = headers.get("server", "")
        if "nginx" in server:
            technologies.setdefault("Web Server", []).append("Nginx")
        elif "apache" in server:
            technologies.setdefault("Web Server", []).append("Apache")
        elif "cloudflare" in server:
            technologies.setdefault("CDN", []).append("Cloudflare")
        
        powered = headers.get("x-powered-by", "")
        if "php" in powered:
            technologies.setdefault("Backend", []).append("PHP")
        elif "node" in powered:
            technologies.setdefault("Backend", []).append("Node.js")
        
        # ── HTML detection ──
        if "wp-content" in html or "wordpress" in html:
            technologies.setdefault("CMS", []).append("WordPress")
        if "drupal" in html:
            technologies.setdefault("CMS", []).append("Drupal")
        if "joomla" in html:
            technologies.setdefault("CMS", []).append("Joomla")
        if "shopify" in html:
            technologies.setdefault("E-commerce", []).append("Shopify")
        
        if "react" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("React")
        if "next" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Next.js")
        if "vue" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Vue.js")
        if "angular" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Angular")
        
        if "tailwind" in html:
            technologies.setdefault("CSS Frameworks", []).append("Tailwind CSS")
        if "bootstrap" in html:
            technologies.setdefault("CSS Frameworks", []).append("Bootstrap")
        
        # ── Wappalyzer (if available) ──
        try:
            from wappalyzer import Wappalyzer
            
            wappalyzer = Wappalyzer()
            results = wappalyzer.analyze(url)
            
            print(f"[Tech Detection] Wappalyzer: {len(results)} technologies")
            
            category_map = {
                'JavaScript Frameworks': 'JavaScript Frameworks',
                'Web Frameworks': 'Web Frameworks',
                'CSS Frameworks': 'CSS Frameworks',
                'UI Frameworks': 'UI Frameworks',
                'JavaScript Libraries': 'JavaScript Libraries',
                'Web Servers': 'Web Servers',
                'CDN': 'CDN',
                'Analytics': 'Analytics',
                'CMS': 'CMS',
                'PaaS': 'PaaS',
                'Font Scripts': 'Font Scripts'
            }
            
            for tech_name, tech_data in results.items():
                if not tech_name:
                    continue
                
                categories = tech_data.get('categories', [])
                version = tech_data.get('version', '')
                display_name = f"{tech_name} {version}" if version else tech_name
                
                matched_category = 'Other'
                for cat in categories:
                    cat_name = cat.get('name', '')
                    for key, value in category_map.items():
                        if key.lower() in cat_name.lower() or cat_name.lower() in key.lower():
                            matched_category = value
                            break
                    if matched_category != 'Other':
                        break
                
                if matched_category not in technologies:
                    technologies[matched_category] = []
                if display_name not in technologies[matched_category]:
                    technologies[matched_category].append(display_name)
                    
        except Exception as e:
            print(f"[Tech Detection] Wappalyzer skipped: {e}")
        
        # ── Remove duplicates ──
        for key in technologies:
            technologies[key] = list(set(technologies[key]))
        
        total = sum(len(v) for v in technologies.values())
        print(f"[Tech Detection] Total: {total} technologies")
        
        return TechDetectionResult(url=url, technologies=technologies, total_found=total)
        
    except Exception as e:
        print(f"[Tech Detection] Error: {e}")
        return TechDetectionResult(url=url, error=str(e))
