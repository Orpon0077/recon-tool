import re
import requests
from app.models import TechDetectionResult

def detect_technologies(url: str) -> TechDetectionResult:
    try:
        response = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        html = response.text
        html_lower = html.lower()
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        technologies = {}
        
        # Web Server Detection
        server = headers.get('server', '').lower()
        if 'gws' in server or 'google' in server:
            technologies["Web Server"] = ["Google Web Server (GWS)"]
        elif 'nginx' in server:
            technologies["Web Server"] = ["Nginx"]
        elif 'apache' in server:
            technologies["Web Server"] = ["Apache"]
        elif 'cloudflare' in server:
            technologies["Web Server"] = ["Cloudflare"]
        
        # Backend Detection
        if 'x-powered-by' in headers:
            powered = headers['x-powered-by']
            if 'next' in powered.lower():
                technologies["Backend"] = ["Next.js"]
            elif 'node' in powered.lower():
                technologies["Backend"] = ["Node.js"]
            elif 'php' in powered.lower():
                technologies["Backend"] = ["PHP"]
            elif 'express' in powered.lower():
                technologies["Backend"] = ["Express"]
        elif 'gws' in server:
            technologies["Backend"] = ["Google Backend"]
        
        # JavaScript Framework Detection
        js_frameworks = []
        if re.search(r'react|__react|data-react', html_lower, re.IGNORECASE):
            js_frameworks.append("React")
        if re.search(r'_next|__next|next\.js', html_lower, re.IGNORECASE):
            js_frameworks.append("Next.js")
        if re.search(r'vue|__vue|data-v-', html_lower, re.IGNORECASE):
            js_frameworks.append("Vue.js")
        if re.search(r'angular|ng-version', html_lower, re.IGNORECASE):
            js_frameworks.append("Angular")
        if js_frameworks:
            technologies["JavaScript Framework"] = js_frameworks
        
        # CDN Detection
        if 'x-amz-cf-id' in headers:
            technologies["CDN"] = ["AWS CloudFront"]
        elif 'cf-ray' in headers:
            technologies["CDN"] = ["Cloudflare"]
        elif 'x-cache' in headers:
            technologies["CDN"] = ["CDN Detected"]
        
        # Protocol Detection
        if 'alt-svc' in headers:
            if 'h3' in headers['alt-svc']:
                technologies["Protocol"] = ["HTTP/3"]
        
        # Security Headers Detection
        security_features = []
        if 'strict-transport-security' in headers:
            security_features.append("HSTS")
        if 'content-security-policy' in headers:
            security_features.append("CSP")
        if 'x-frame-options' in headers:
            security_features.append("X-Frame-Options")
        if security_features:
            technologies["Security"] = security_features
        
        # CMS Detection
        if 'wp-content' in html_lower or 'wordpress' in html_lower:
            technologies["CMS"] = ["WordPress"]
        elif 'drupal' in html_lower:
            technologies["CMS"] = ["Drupal"]
        elif 'joomla' in html_lower:
            technologies["CMS"] = ["Joomla"]
        
        total = sum(len(v) for v in technologies.values())
        
        return TechDetectionResult(
            url=url,
            technologies=technologies,
            total_found=total,
        )
    except Exception as e:
        return TechDetectionResult(url=url, error=str(e))
