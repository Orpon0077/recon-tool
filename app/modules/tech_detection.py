# ── Tech Detection Module with Playwright ──
import re
import requests
from bs4 import BeautifulSoup
from app.models import TechDetectionResult

# TECH_RULES for direct detection
TECH_RULES = [
    # Web Server
    {"category": "Web Server", "name": "Nginx", "check": "header", "header": "server", "pattern": r"nginx[/ ]?([\d.]+)?"},
    {"category": "Web Server", "name": "Apache", "check": "header", "header": "server", "pattern": r"apache[/ ]?([\d.]+)?"},
    {"category": "Web Server", "name": "Cloudflare", "check": "header", "header": "server", "pattern": r"cloudflare"},
    
    # Backend
    {"category": "Backend", "name": "Node.js", "check": "header", "header": "x-powered-by", "pattern": r"node[/ ]?([\d.]+)?"},
    {"category": "Backend", "name": "Next.js", "check": "header", "header": "x-powered-by", "pattern": r"next\.js"},
    {"category": "Backend", "name": "PHP", "check": "header", "header": "x-powered-by", "pattern": r"php[/ ]?([\d.]+)?"},
    
    # CDN
    {"category": "CDN", "name": "Cloudflare", "check": "header", "header": "cf-ray", "pattern": r".*"},
    {"category": "CDN", "name": "AWS CloudFront", "check": "header", "header": "x-amz-cf-id", "pattern": r".*"},
    
    # JavaScript Framework
    {"category": "JavaScript Framework", "name": "React", "check": "html", "pattern": r"react|__react|data-react"},
    {"category": "JavaScript Framework", "name": "Next.js", "check": "html", "pattern": r"_next/static|__next"},
    {"category": "JavaScript Framework", "name": "Vue.js", "check": "html", "pattern": r"vue|__vue"},
    
    # Hosting
    {"category": "Hosting", "name": "AWS", "check": "header", "header": "x-amzn-requestid", "pattern": r".*"},
    {"category": "Hosting", "name": "AWS", "check": "html", "pattern": r"amazonaws\.com"},
    
    # Protocol
    {"category": "Protocol", "name": "HTTP/3", "check": "header", "header": "alt-svc", "pattern": r"h3"},
    
    # CMS
    {"category": "CMS", "name": "WordPress", "check": "html", "pattern": r"wp-content|wp-includes"},
    {"category": "CMS", "name": "Shopify", "check": "html", "pattern": r"shopify"},
    
    # UI Framework
    {"category": "UI Framework", "name": "Tailwind CSS", "check": "html", "pattern": r"tailwind"},
    {"category": "UI Framework", "name": "Bootstrap", "check": "html", "pattern": r"bootstrap"},
    {"category": "UI Framework", "name": "Material UI", "check": "html", "pattern": r"mui|material-ui"},
    
    # Analytics
    {"category": "Analytics", "name": "Google Analytics", "check": "html", "pattern": r"google-analytics|gtag"},
    {"category": "Analytics", "name": "Facebook Pixel", "check": "html", "pattern": r"facebook\.net/tr|fbq"},
]


def detect_technologies(url: str) -> TechDetectionResult:
    """Detect technologies using Playwright and direct rules"""
    try:
        from playwright.sync_api import sync_playwright
        
        print(f"[DEBUG] Scanning: {url}")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=45000)
            html_content = page.content()
            
            # Get response headers via requests
            response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            browser.close()
        
        # Parse HTML
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Get meta content
        meta_content = " ".join([
            f"{tag.get('name', '')} {tag.get('content', '')}"
            for tag in soup.find_all("meta")
        ])
        
        technologies = {}
        
        # Apply rules
        for rule in TECH_RULES:
            category = rule["category"]
            name = rule["name"]
            check = rule["check"]
            pattern = rule["pattern"]
            
            found = False
            version = ""
            
            if check == "header":
                header_val = headers.get(rule.get("header", ""), "")
                if header_val:
                    match = re.search(pattern, header_val, re.IGNORECASE)
                    if match:
                        found = True
                        if match.groups() and match.group(1):
                            version = match.group(1)
            
            elif check == "html":
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    found = True
                    if match.groups() and match.group(1):
                        version = match.group(1)
            
            if found:
                if category not in technologies:
                    technologies[category] = []
                display = f"{name} {version}".strip() if version else name
                if display not in technologies[category]:
                    technologies[category].append(display)
        
        # Manual detection for common frameworks
        if "_next" in html_content or "next" in html_content.lower():
            if "JavaScript Framework" not in technologies:
                technologies["JavaScript Framework"] = []
            if "Next.js" not in technologies["JavaScript Framework"]:
                technologies["JavaScript Framework"].append("Next.js")
        
        if "react" in html_content.lower():
            if "JavaScript Framework" not in technologies:
                technologies["JavaScript Framework"] = []
            if "React" not in technologies["JavaScript Framework"]:
                technologies["JavaScript Framework"].append("React")
        
        # AWS detection from CDN
        if "AWS CloudFront" in technologies.get("CDN", []):
            if "Hosting" not in technologies:
                technologies["Hosting"] = []
            if "AWS" not in technologies["Hosting"]:
                technologies["Hosting"].append("AWS")
        
        total = sum(len(v) for v in technologies.values())
        
        print(f"[DEBUG] Found {total} technologies")
        for cat, techs in technologies.items():
            print(f"  {cat}: {', '.join(techs)}")
        
        return TechDetectionResult(
            url=url,
            technologies=technologies,
            total_found=total,
        )
        
    except Exception as e:
        print(f"Error: {e}")
        return TechDetectionResult(url=url, error=str(e))