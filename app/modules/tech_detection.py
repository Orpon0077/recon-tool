# ── Tech Detection Module ──────────────────────────────────
# Headers, HTML, Scripts দেখে technology আর version detect করে

import re
import requests
from bs4 import BeautifulSoup
from app.models import TechDetectionResult

TECH_RULES = [
    # ── Web Server ────────────────────────────────────────
    {"category": "Web Server",     "name": "Nginx",          "check": "header",    "header": "server",         "pattern": r"nginx[/ ]?([\d.]+)?"},
    {"category": "Web Server",     "name": "Apache",         "check": "header",    "header": "server",         "pattern": r"apache[/ ]?([\d.]+)?"},
    {"category": "Web Server",     "name": "IIS",            "check": "header",    "header": "server",         "pattern": r"iis[/ ]?([\d.]+)?"},
    {"category": "Web Server",     "name": "Cloudflare",     "check": "header",    "header": "server",         "pattern": r"cloudflare"},
    {"category": "Web Server",     "name": "LiteSpeed",      "check": "header",    "header": "server",         "pattern": r"litespeed[/ ]?([\d.]+)?"},
    {"category": "Web Server",     "name": "OpenResty",      "check": "header",    "header": "server",         "pattern": r"openresty[/ ]?([\d.]+)?"},

    # ── Backend ───────────────────────────────────────────
    {"category": "Backend",        "name": "PHP",            "check": "header",    "header": "x-powered-by",   "pattern": r"php[/ ]?([\d.]+)?"},
    {"category": "Backend",        "name": "Node.js",        "check": "header",    "header": "x-powered-by",   "pattern": r"node[/ ]?([\d.]+)?"},
    {"category": "Backend",        "name": "Express",        "check": "header",    "header": "x-powered-by",   "pattern": r"express[/ ]?([\d.]+)?"},
    {"category": "Backend",        "name": "Next.js",        "check": "header",    "header": "x-powered-by",   "pattern": r"next\.js[/ ]?([\d.]+)?"},
    {"category": "Backend",        "name": "ASP.NET",        "check": "header",    "header": "x-powered-by",   "pattern": r"asp\.net[/ ]?([\d.]+)?"},
    {"category": "Backend",        "name": "Next.js",        "check": "header",    "header": "x-nextjs-cache", "pattern": r".*"},

    # ── CDN ───────────────────────────────────────────────
    {"category": "CDN",            "name": "Cloudflare",     "check": "header",    "header": "cf-ray",          "pattern": r".*"},
    {"category": "CDN",            "name": "AWS CloudFront", "check": "header",    "header": "x-amz-cf-id",     "pattern": r".*"},
    {"category": "CDN",            "name": "Vercel",         "check": "header",    "header": "x-vercel-id",     "pattern": r".*"},
    {"category": "CDN",            "name": "Netlify",        "check": "header",    "header": "x-nf-request-id", "pattern": r".*"},
    {"category": "CDN",            "name": "Fastly",         "check": "header",    "header": "x-served-by",     "pattern": r"cache"},

    # ── Hosting / PaaS ────────────────────────────────────
    {"category": "Hosting",        "name": "AWS",            "check": "header",    "header": "x-amzn-requestid","pattern": r".*"},
    {"category": "Hosting",        "name": "Vercel",         "check": "header",    "header": "x-vercel-cache",  "pattern": r".*"},
    {"category": "Hosting",        "name": "GitHub Pages",   "check": "header",    "header": "x-github-request-id","pattern": r".*"},

    # ── CMS ───────────────────────────────────────────────
    {"category": "CMS",            "name": "WordPress",      "check": "html",      "pattern": r"wp-content|wp-includes"},
    {"category": "CMS",            "name": "WordPress",      "check": "meta",      "pattern": r"wordpress"},
    {"category": "CMS",            "name": "Drupal",         "check": "html",      "pattern": r"drupal"},
    {"category": "CMS",            "name": "Joomla",         "check": "html",      "pattern": r"joomla"},
    {"category": "CMS",            "name": "Shopify",        "check": "html",      "pattern": r"shopify"},
    {"category": "CMS",            "name": "Wix",            "check": "html",      "pattern": r"wix\.com"},
    {"category": "CMS",            "name": "Squarespace",    "check": "html",      "pattern": r"squarespace"},
    {"category": "CMS",            "name": "Ghost",          "check": "meta",      "pattern": r"ghost"},
    {"category": "CMS",            "name": "Webflow",        "check": "html",      "pattern": r"webflow"},

    # ── JavaScript Framework ──────────────────────────────
    {"category": "JavaScript Framework", "name": "React",    "check": "html",      "pattern": r"react(?:\.min)?\.js|__react|data-react"},
    {"category": "JavaScript Framework", "name": "Vue.js",   "check": "html",      "pattern": r"vue(?:\.min)?\.js|__vue"},
    {"category": "JavaScript Framework", "name": "Angular",  "check": "html",      "pattern": r"angular(?:\.min)?\.js|ng-version"},
    {"category": "JavaScript Framework", "name": "Next.js",  "check": "html",      "pattern": r"_next/static|__next"},
    {"category": "JavaScript Framework", "name": "Nuxt.js",  "check": "html",      "pattern": r"__nuxt|_nuxt"},
    {"category": "JavaScript Framework", "name": "Svelte",   "check": "html",      "pattern": r"svelte"},
    {"category": "JavaScript Framework", "name": "Ember.js", "check": "html",      "pattern": r"ember(?:\.min)?\.js"},

    # ── JavaScript Library ────────────────────────────────
    {"category": "JavaScript Library",   "name": "jQuery",   "check": "html",      "pattern": r"jquery[.-]([\d.]+)?(?:\.min)?\.js"},
    {"category": "JavaScript Library",   "name": "Lodash",   "check": "html",      "pattern": r"lodash"},
    {"category": "JavaScript Library",   "name": "Axios",    "check": "html",      "pattern": r"axios"},
    {"category": "JavaScript Library",   "name": "Three.js", "check": "html",      "pattern": r"three(?:\.min)?\.js"},
    {"category": "JavaScript Library",   "name": "D3.js",    "check": "html",      "pattern": r"d3(?:\.min)?\.js"},

    # ── UI Framework ──────────────────────────────────────
    {"category": "UI Framework",   "name": "Tailwind CSS",   "check": "html",      "pattern": r"tailwind"},
    {"category": "UI Framework",   "name": "Bootstrap",      "check": "html",      "pattern": r"bootstrap(?:\.min)?\.css"},
    {"category": "UI Framework",   "name": "Material UI",    "check": "html",      "pattern": r"mui|material-ui"},
    {"category": "UI Framework",   "name": "Chakra UI",      "check": "html",      "pattern": r"chakra"},
    {"category": "UI Framework",   "name": "Ant Design",     "check": "html",      "pattern": r"antd"},

    # ── Analytics ─────────────────────────────────────────
    {"category": "Analytics",      "name": "Google Analytics","check": "html",     "pattern": r"google-analytics\.com|gtag\("},
    {"category": "Analytics",      "name": "Google Tag Manager","check": "html",   "pattern": r"googletagmanager\.com"},
    {"category": "Analytics",      "name": "Facebook Pixel", "check": "html",      "pattern": r"connect\.facebook\.net|fbq\("},
    {"category": "Analytics",      "name": "Hotjar",         "check": "html",      "pattern": r"hotjar"},
    {"category": "Analytics",      "name": "Mixpanel",       "check": "html",      "pattern": r"mixpanel"},
    {"category": "Analytics",      "name": "Segment",        "check": "html",      "pattern": r"segment\.com|analytics\.js"},
    {"category": "Analytics",      "name": "Plausible",      "check": "html",      "pattern": r"plausible"},
    {"category": "Analytics",      "name": "Clarity",        "check": "html",      "pattern": r"clarity\.ms"},

    # ── Font Service ──────────────────────────────────────
    {"category": "Font Service",   "name": "Google Fonts",   "check": "html",      "pattern": r"fonts\.googleapis\.com"},
    {"category": "Font Service",   "name": "Font Awesome",   "check": "html",      "pattern": r"fontawesome"},
    {"category": "Font Service",   "name": "Adobe Fonts",    "check": "html",      "pattern": r"typekit|use\.typekit"},

    # ── Payment ───────────────────────────────────────────
    {"category": "Payment",        "name": "Stripe",         "check": "html",      "pattern": r"stripe\.com|stripe\.js"},
    {"category": "Payment",        "name": "PayPal",         "check": "html",      "pattern": r"paypal\.com"},
    {"category": "Payment",        "name": "Paddle",         "check": "html",      "pattern": r"paddle\.com"},

    # ── Security ──────────────────────────────────────────
    {"category": "Security",       "name": "reCAPTCHA",      "check": "html",      "pattern": r"recaptcha"},
    {"category": "Security",       "name": "hCaptcha",       "check": "html",      "pattern": r"hcaptcha"},
    {"category": "Security",       "name": "Cloudflare Turnstile","check": "html", "pattern": r"turnstile"},

    # ── Chat / Support ────────────────────────────────────
    {"category": "Chat",           "name": "Intercom",       "check": "html",      "pattern": r"intercom"},
    {"category": "Chat",           "name": "Zendesk",        "check": "html",      "pattern": r"zendesk"},
    {"category": "Chat",           "name": "Drift",          "check": "html",      "pattern": r"drift\.com"},
    {"category": "Chat",           "name": "Crisp",          "check": "html",      "pattern": r"crisp\.chat"},
    {"category": "Chat",           "name": "Tawk.to",        "check": "html",      "pattern": r"tawk\.to"},

    # ── Map Service ───────────────────────────────────────
    {"category": "Map Service",    "name": "Google Maps",    "check": "html",      "pattern": r"maps\.googleapis\.com"},
    {"category": "Map Service",    "name": "Mapbox",         "check": "html",      "pattern": r"mapbox"},
    {"category": "Map Service",    "name": "Leaflet",        "check": "html",      "pattern": r"leaflet"},

    # ── Video ─────────────────────────────────────────────
    {"category": "Video",          "name": "YouTube",        "check": "html",      "pattern": r"youtube\.com/embed"},
    {"category": "Video",          "name": "Vimeo",          "check": "html",      "pattern": r"vimeo\.com"},
    {"category": "Video",          "name": "Wistia",         "check": "html",      "pattern": r"wistia"},

    # ── Cookie ────────────────────────────────────────────
    {"category": "Backend",        "name": "PHP",            "check": "cookie",    "pattern": r"phpsessid"},
    {"category": "CMS",            "name": "WordPress",      "check": "cookie",    "pattern": r"wordpress"},
]


def get_js_content(soup, base_url: str) -> str:
    """
    Page এর সব JavaScript files এর content নিয়ে আসো।
    """
    js_content = ""
    script_tags = soup.find_all("script", src=True)

    for script in script_tags[:5]:
        src = script.get("src", "")
        if src.startswith("/"):
            src = base_url.rstrip("/") + src
        elif not src.startswith("http"):
            continue
        try:
            resp = requests.get(src, timeout=5, verify=False)
            js_content += resp.text[:50000]
        except Exception:
            continue

    return js_content


def detect_technologies(url: str) -> TechDetectionResult:
    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            allow_redirects=True,
        )

        # সব headers lowercase করো
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # HTML content
        html_content = response.text

        # BeautifulSoup দিয়ে parse করো
        soup = BeautifulSoup(html_content, "html.parser")

        # Meta tags
        meta_content = " ".join([
            f"{tag.get('name', '')} {tag.get('content', '')}"
            for tag in soup.find_all("meta")
        ])

        # JavaScript files এর content নিয়ে আসো
        js_content = get_js_content(soup, url)

        # HTML + JS একসাথে check করো
        full_content = html_content + js_content

        # Cookies
        cookies = {k.lower(): v for k, v in response.cookies.items()}

        technologies: dict[str, list[str]] = {}

        for rule in TECH_RULES:
            category = rule["category"]
            name = rule["name"]
            check = rule["check"]
            pattern = rule["pattern"]

            found = False
            version = ""

            # ── Header check ──────────────────────────────
            if check == "header":
                header_value = resp_headers.get(rule.get("header", ""), "")
                if header_value:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        found = True
                        if match.groups():
                            v = match.group(1)
                            if v:
                                version = v.strip("./- ")

            # ── HTML check ────────────────────────────────
            elif check == "html":
                match = re.search(pattern, full_content, re.IGNORECASE)
                if match:
                    found = True
                    if match.groups():
                        v = match.group(1)
                        if v:
                            version = v.strip("./- ")

            # ── Meta check ────────────────────────────────
            elif check == "meta":
                if re.search(pattern, meta_content, re.IGNORECASE):
                    found = True

            # ── Cookie check ──────────────────────────────
            elif check == "cookie":
                for cookie_name in cookies:
                    if re.search(pattern, cookie_name, re.IGNORECASE):
                        found = True
                        break

            # ── Detected হলে যোগ করো ──────────────────────
            if found:
                if category not in technologies:
                    technologies[category] = []

                display_name = f"{name} {version}".strip() if version else name

                if display_name not in technologies[category]:
                    technologies[category].append(display_name)

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
    except Exception as e:
        return TechDetectionResult(url=url, error=str(e))