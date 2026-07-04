import requests
from bs4 import BeautifulSoup
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import TechDetectionResult
from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def detect_technologies(url: str) -> TechDetectionResult:
    try:
        url = normalize_url(url)
        technologies = {}
        
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # ── ১. হেডার ডিটেকশন ──
        server = headers.get("server", "")
        if "nginx" in server:
            technologies.setdefault("Web Servers", []).append("Nginx")
        elif "apache" in server:
            technologies.setdefault("Web Servers", []).append("Apache")
        elif "cloudflare" in server:
            technologies.setdefault("CDN", []).append("Cloudflare")
        elif "gws" in server:
            technologies.setdefault("Web Servers", []).append("Google Web Server")
        
        powered = headers.get("x-powered-by", "")
        if "php" in powered:
            technologies.setdefault("Backend", []).append("PHP")
        elif "node" in powered:
            technologies.setdefault("Backend", []).append("Node.js")
        elif "asp.net" in powered:
            technologies.setdefault("Backend", []).append("ASP.NET")
        
        # ── ২. HTML/মেটা ডিটেকশন ──
        if "wp-content" in html or "wordpress" in html:
            technologies.setdefault("CMS", []).append("WordPress")
        if "drupal" in html:
            technologies.setdefault("CMS", []).append("Drupal")
        if "joomla" in html:
            technologies.setdefault("CMS", []).append("Joomla")
        if "shopify" in html:
            technologies.setdefault("E-commerce", []).append("Shopify")
        if "magento" in html:
            technologies.setdefault("E-commerce", []).append("Magento")
        
        if "react" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("React")
        if "next" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Next.js")
        if "vue" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Vue.js")
        if "angular" in html:
            technologies.setdefault("JavaScript Frameworks", []).append("Angular")
        if "jquery" in html:
            technologies.setdefault("JavaScript Libraries", []).append("jQuery")
        if "bootstrap" in html:
            technologies.setdefault("CSS Frameworks", []).append("Bootstrap")
        if "tailwind" in html:
            technologies.setdefault("CSS Frameworks", []).append("Tailwind CSS")
        
        # ── ৩. Wappalyzer (যদি ইনস্টল করা থাকে) ──
        try:
            from wappalyzer import Wappalyzer, WebPage
            
            wappalyzer = Wappalyzer()
            webpage = WebPage(url)
            results = wappalyzer.analyze(webpage)
            
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
                'Font Scripts': 'Font Scripts',
                'E-commerce': 'E-commerce',
                'Backend': 'Backend',
                'Security': 'Security',
                'Other': 'Other'
            }
            
            for tech_name, tech_data in results.items():
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
                    
        except ImportError:
            print("[Tech Detection] Wappalyzer module not installed. Skipping.")
        except Exception as e:
            print(f"[Tech Detection] Wappalyzer error: {e}")
        
        # ── ৪. ডুপ্লিকেট রিমুভ ──
        for key in technologies:
            technologies[key] = list(set(technologies[key]))
        
        total = sum(len(v) for v in technologies.values())
        print(f"[Tech Detection] Total: {total} technologies")
        
        return TechDetectionResult(
            url=url,
            technologies=technologies,
            total_found=total
        )
        
    except Exception as e:
        print(f"[Tech Detection] Error: {e}")
        return TechDetectionResult(url=url, error=str(e))