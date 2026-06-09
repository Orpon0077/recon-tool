# ── Tech Detection Module ──────────────────────────────────
# Website এ কোন technology use হচ্ছে detect করে

import requests
from bs4 import BeautifulSoup    
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS 
from app.models import TechDetectionResult

# ── Detection Rules ────────────────────────────────────────
# প্রতিটা rule এ আছে:
# - category: কোন ধরনের technology
# - name: technology এর নাম
# - check: কোথায় খুঁজব
# - pattern: কী খুঁজব

TECH_RULES = [
    # ── Web Server ────────────────────────────────────────
    {"category": "Web Server",  "name": "Nginx",       "check": "header", "header": "server",       "pattern": "nginx"},
    {"category": "Web Server",  "name": "Apache",      "check": "header", "header": "server",       "pattern": "apache"},
    {"category": "Web Server",  "name": "IIS",         "check": "header", "header": "server",       "pattern": "iis"},
    {"category": "Web Server",  "name": "Cloudflare",  "check": "header", "header": "server",       "pattern": "cloudflare"},

    # ── Backend ───────────────────────────────────────────
    {"category": "Backend",     "name": "PHP",         "check": "header", "header": "x-powered-by", "pattern": "php"},
    {"category": "Backend",     "name": "Node.js",     "check": "header", "header": "x-powered-by", "pattern": "node"},
    {"category": "Backend",     "name": "Express",     "check": "header", "header": "x-powered-by", "pattern": "express"},
    {"category": "Backend",     "name": "Next.js",     "check": "header", "header": "x-powered-by", "pattern": "next"},
    {"category": "Backend",     "name": "ASP.NET",     "check": "header", "header": "x-powered-by", "pattern": "asp.net"},

    # ── CDN ───────────────────────────────────────────────
    {"category": "CDN",         "name": "Cloudflare",  "check": "header", "header": "cf-ray",        "pattern": ""},
    {"category": "CDN",         "name": "AWS CloudFront","check": "header","header": "x-amz-cf-id",  "pattern": ""},

    # ── CMS ───────────────────────────────────────────────
    {"category": "CMS",         "name": "WordPress",   "check": "html",   "pattern": "wp-content"},
    {"category": "CMS",         "name": "WordPress",   "check": "meta",   "pattern": "wordpress"},
    {"category": "CMS",         "name": "Drupal",      "check": "html",   "pattern": "drupal"},
    {"category": "CMS",         "name": "Joomla",      "check": "html",   "pattern": "joomla"},
    {"category": "CMS",         "name": "Shopify",     "check": "html",   "pattern": "shopify"},
    {"category": "CMS",         "name": "Wix",         "check": "html",   "pattern": "wix.com"},
    {"category": "CMS",         "name": "Squarespace", "check": "html",   "pattern": "squarespace"},

    # ── Frontend Framework ────────────────────────────────
    {"category": "Frontend",    "name": "React",       "check": "html",   "pattern": "react"},
    {"category": "Frontend",    "name": "Vue.js",      "check": "html",   "pattern": "vue"},
    {"category": "Frontend",    "name": "Angular",     "check": "html",   "pattern": "angular"},
    {"category": "Frontend",    "name": "jQuery",      "check": "html",   "pattern": "jquery"},
    {"category": "Frontend",    "name": "Bootstrap",   "check": "html",   "pattern": "bootstrap"},

    # ── Analytics ─────────────────────────────────────────
    {"category": "Analytics",   "name": "Google Analytics","check": "html","pattern": "google-analytics"},
    {"category": "Analytics",   "name": "Google Analytics","check": "html","pattern": "gtag"},
    {"category": "Analytics",   "name": "Hotjar",      "check": "html",   "pattern": "hotjar"},
    {"category": "Analytics",   "name": "Mixpanel",    "check": "html",   "pattern": "mixpanel"},

    # ── Cookie ────────────────────────────────────────────
    {"category": "Backend",     "name": "PHP",         "check": "cookie", "pattern": "phpsessid"},
    {"category": "CMS",         "name": "WordPress",   "check": "cookie", "pattern": "wordpress"},
]


def detect_technologies(url: str) -> TechDetectionResult:
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )

        # সব headers lowercase করো
        resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        # HTML content lowercase করো
        html_content = response.text.lower()

        # Cookies lowercase করো
        cookies = {k.lower(): v.lower() for k, v in response.cookies.items()}

        # BeautifulSoup দিয়ে meta tags পড়ো
        soup = BeautifulSoup(response.text, "html.parser")
        meta_content = " ".join([
            str(tag.get("content", "")).lower()
            for tag in soup.find_all("meta")
        ])

        technologies: dict[str, list[str]] = {}

        for rule in TECH_RULES:
            category = rule["category"]
            name = rule["name"]
            check = rule["check"]
            pattern = rule["pattern"]

            found = False

            # ── Header check ──────────────────────────────
            if check == "header":
                header_value = resp_headers.get(rule["header"], "")
                if pattern == "" and header_value:
                    found = True
                elif pattern and pattern in header_value:
                    found = True

            # ── HTML check ────────────────────────────────
            elif check == "html":
                if pattern in html_content:
                    found = True

            # ── Meta tag check ────────────────────────────
            elif check == "meta":
                if pattern in meta_content:
                    found = True

            # ── Cookie check ──────────────────────────────
            elif check == "cookie":
                for cookie_name in cookies:
                    if pattern in cookie_name:
                        found = True
                        break

            # ── Detected হলে যোগ করো ─────────────────────
            if found:
                if category not in technologies:
                    technologies[category] = []
                if name not in technologies[category]:
                    technologies[category].append(name)

        total = sum(len(v) for v in technologies.values())

        return TechDetectionResult(
            url=url,
            technologies=technologies,
            total_found=total,
        )

    except requests.exceptions.ConnectionError:
        return TechDetectionResult(url=url, error="Connection failed")
    except requests.exceptions.Timeout:
        return TechDetectionResult(url=url, error="Request timed out")
    except requests.exceptions.RequestException as e:
        return TechDetectionResult(url=url, error=str(e))