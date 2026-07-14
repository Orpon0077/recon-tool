import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import Dict, List, Optional

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def detect_technologies(url: str) -> dict:
    """
    Detect technologies using:
    1. Headers
    2. HTML patterns
    3. Wappalyzer (if available, fallback silently)
    """
    url = normalize_url(url)
    technologies = {}

    try:
        response = requests.get(url, timeout=30, allow_redirects=True)  # ← timeout 30
        headers = {k.lower(): v for k, v in response.headers.items()}
        html = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        return {"technologies": {}, "total_found": 0, "error": str(e)}

    # Header detection
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
    elif "express" in powered:
        technologies.setdefault("Backend", []).append("Express.js")

    # HTML meta detection
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

    # JavaScript frameworks
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

    # CSS frameworks
    if "bootstrap" in html:
        technologies.setdefault("CSS Frameworks", []).append("Bootstrap")
    if "tailwind" in html:
        technologies.setdefault("CSS Frameworks", []).append("Tailwind CSS")

    # Wappalyzer (silent fallback)
    try:
        from wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer()
        webpage = WebPage(url)
        results = wappalyzer.analyze(webpage)
        if results:
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
                'E-commerce': 'E-commerce',
                'PaaS': 'PaaS',
                'Font Scripts': 'Font Scripts'
            }
            for tech_name, tech_data in results.items():
                if not tech_name:
                    continue
                categories = tech_data.get('categories', [])
                version = tech_data.get('version', '')
                display_name = f"{tech_name}{' ' + version if version else ''}"
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
    except Exception:
        # Wappalyzer not available or error – ignore
        pass

    # Remove duplicates
    for key in technologies:
        technologies[key] = list(set(technologies[key]))

    total = sum(len(v) for v in technologies.values())
    return {
        "technologies": technologies,
        "total_found": total
    }