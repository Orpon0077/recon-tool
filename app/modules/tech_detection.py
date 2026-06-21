import requests
from bs4 import BeautifulSoup
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import TechDetectionResult

def detect_technologies(url: str) -> TechDetectionResult:
    try:
        technologies = {}
        
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text.lower()
        
        # ── Headers detection ──
        server = headers.get("server", "")
        if "nginx" in server.lower():
            technologies.setdefault("Web Server", []).append("Nginx")
        elif "apache" in server.lower():
            technologies.setdefault("Web Server", []).append("Apache")
        elif "cloudflare" in server.lower():
            technologies.setdefault("CDN", []).append("Cloudflare")
        
        powered = headers.get("x-powered-by", "")
        if "php" in powered.lower():
            technologies.setdefault("Backend", []).append("PHP")
        elif "node" in powered.lower():
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
        if "vue" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Vue.js")
        if "angular" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Angular")
        if "next" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Next.js")
        
        if "bootstrap" in html:
            technologies.setdefault("CSS Frameworks", []).append("Bootstrap")
        if "tailwind" in html:
            technologies.setdefault("CSS Frameworks", []).append("Tailwind CSS")
        
        # ── Wappalyzer (without Playwright) ──
        try:
            # Use requests-based wappalyzer
            from wappalyzer import Wappalyzer
            
            print("[Tech Detection] Running Wappalyzer (requests mode)...")
            
            # Disable playwright for wappalyzer
            wappalyzer = Wappalyzer()
            
            # Use custom session to avoid playwright
            session = requests.Session()
            session.headers.update(REQUEST_HEADERS)
            
            # Analyze using requests
            results = wappalyzer.analyze(url, session=session)
            
            print(f"[Tech Detection] Wappalyzer found {len(results)} technologies")
            
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
                'Font Scripts': 'Font Scripts',
                'Miscellaneous': 'Miscellaneous'
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
        
        print(f"[Tech Detection] Total: {total} technologies found")
        
        return TechDetectionResult(
            url=url,
            technologies=technologies,
            total_found=total,
        )
        
    except Exception as e:
        print(f"[Tech Detection] Error: {e}")
        return TechDetectionResult(url=url, error=str(e))
