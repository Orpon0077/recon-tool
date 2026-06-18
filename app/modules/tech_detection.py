import re
import requests
from bs4 import BeautifulSoup
from app.models import TechDetectionResult

# Version extraction patterns
VERSION_PATTERNS = {
    "React": [r'react@([\d.]+)', r'react[\s-]+v?([\d.]+)', r'React v([\d.]+)'],
    "Next.js": [r'next@([\d.]+)', r'next[\s-]+v?([\d.]+)', r'Next\.js v([\d.]+)'],
    "Vue.js": [r'vue@([\d.]+)', r'vue[\s-]+v?([\d.]+)'],
    "Angular": [r'angular@([\d.]+)', r'@angular/core@([\d.]+)'],
    "Node.js": [r'node@([\d.]+)', r'node[\s-]+v?([\d.]+)'],
    "PHP": [r'php([\d.]+)', r'php[\s-]+v?([\d.]+)'],
    "jQuery": [r'jquery@([\d.]+)', r'jquery[\s-]+([\d.]+)'],
    "Bootstrap": [r'bootstrap@([\d.]+)', r'bootstrap[\s-]+([\d.]+)'],
    "Tailwind": [r'tailwindcss@([\d.]+)', r'tailwind[\s-]+([\d.]+)'],
}

def extract_version(tech_name: str, content: str) -> str:
    """Extract version number for a technology"""
    tech_lower = tech_name.lower()
    for key, patterns in VERSION_PATTERNS.items():
        if key.lower() in tech_lower or tech_lower in key.lower():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if version:
                        return version.strip()
    return ""

def detect_technologies(url: str) -> TechDetectionResult:
    """Detect technologies with version numbers"""
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            html_content = page.content()
            
            # Get all JS files content for version detection
            js_urls = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(src => src && (src.endsWith('.js') || src.includes('.js?')));
            }""")
            
            browser.close()
        
        # Get headers
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Collect all JS content for version detection
        all_js_content = ""
        for js_url in js_urls[:10]:
            try:
                resp = requests.get(js_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                all_js_content += resp.text[:100000]
            except:
                pass
        
        # Combine all content
        all_content = html_content + all_js_content
        html_lower = html_content.lower()
        
        technologies = {}
        
        # ── Web Server ──
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            version = extract_version("nginx", server)
            technologies["Web Server"] = [f"Nginx {version}".strip() if version else "Nginx"]
        elif 'apache' in server:
            version = extract_version("apache", server)
            technologies["Web Server"] = [f"Apache {version}".strip() if version else "Apache"]
        elif 'cloudflare' in server:
            technologies["Web Server"] = ["Cloudflare"]
        elif 'gws' in server or 'google' in server:
            technologies["Web Server"] = ["Google Web Server (GWS)"]
        
        # ── Backend ──
        if 'x-powered-by' in headers:
            powered = headers['x-powered-by']
            if 'next' in powered.lower():
                version = extract_version("Next.js", powered)
                technologies["Backend"] = [f"Next.js {version}".strip() if version else "Next.js"]
            elif 'node' in powered.lower():
                version = extract_version("Node.js", powered)
                technologies["Backend"] = [f"Node.js {version}".strip() if version else "Node.js"]
            elif 'php' in powered.lower():
                version = extract_version("PHP", powered)
                technologies["Backend"] = [f"PHP {version}".strip() if version else "PHP"]
            elif 'express' in powered.lower():
                technologies["Backend"] = ["Express"]
        
        # ── JavaScript Framework ──
        js_frameworks = []
        
        # React
        if re.search(r'react|__react|data-react|React\.createElement', html_lower, re.IGNORECASE):
            version = extract_version("React", all_content)
            js_frameworks.append(f"React {version}".strip() if version else "React")
        
        # Next.js
        if re.search(r'_next/static|__next|next/dist', html_lower, re.IGNORECASE):
            version = extract_version("Next.js", all_content)
            js_frameworks.append(f"Next.js {version}".strip() if version else "Next.js")
        
        # Vue.js
        if re.search(r'vue|__vue|data-v-', html_lower, re.IGNORECASE):
            version = extract_version("Vue.js", all_content)
            js_frameworks.append(f"Vue.js {version}".strip() if version else "Vue.js")
        
        # Angular
        if re.search(r'angular|ng-version', html_lower, re.IGNORECASE):
            version = extract_version("Angular", all_content)
            js_frameworks.append(f"Angular {version}".strip() if version else "Angular")
        
        if js_frameworks:
            technologies["JavaScript Framework"] = js_frameworks
        
        # ── CDN ──
        if 'x-amz-cf-id' in headers:
            technologies["CDN"] = ["AWS CloudFront"]
        elif 'cf-ray' in headers:
            technologies["CDN"] = ["Cloudflare"]
        
        # ── Protocol ──
        if 'alt-svc' in headers and 'h3' in headers['alt-svc']:
            technologies["Protocol"] = ["HTTP/3"]
        
        # ── Security ──
        security_features = []
        if 'strict-transport-security' in headers:
            security_features.append("HSTS")
        if 'content-security-policy' in headers:
            security_features.append("CSP")
        if 'x-frame-options' in headers:
            security_features.append("X-Frame-Options")
        if security_features:
            technologies["Security"] = security_features
        
        # ── CMS ──
        if 'wp-content' in html_lower or 'wordpress' in html_lower:
            technologies["CMS"] = ["WordPress"]
        elif 'drupal' in html_lower:
            technologies["CMS"] = ["Drupal"]
        elif 'joomla' in html_lower:
            technologies["CMS"] = ["Joomla"]
        elif 'shopify' in html_lower:
            technologies["CMS"] = ["Shopify"]
        
        # ── Analytics ──
        analytics = []
        if 'google-analytics' in html_lower or 'gtag' in html_lower:
            analytics.append("Google Analytics")
        if 'facebook.net' in html_lower or 'fbq' in html_lower:
            analytics.append("Facebook Pixel")
        if analytics:
            technologies["Analytics"] = analytics
        
        total = sum(len(v) for v in technologies.values())
        
        return TechDetectionResult(
            url=url,
            technologies=technologies,
            total_found=total,
        )
        
    except Exception as e:
        print(f"Tech detection error: {e}")
        return TechDetectionResult(url=url, error=str(e))