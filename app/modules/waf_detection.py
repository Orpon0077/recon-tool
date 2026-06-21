# ── WAF Detection Module (Wappalyzer with DNS fix) ──────
import requests
import sys
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import FirewallResult

# Fix for dns resolver issue
try:
    import dns.resolver
except ImportError:
    pass

def detect_waf_with_wappalyzer(url: str) -> dict:
    """Wappalyzer দিয়ে WAF detect করে (DNS error fixed)"""
    try:
        # Fix DNS issue
        import dns.resolver
        dns.resolver.default_resolver = dns.resolver.Resolver()
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        from wappalyzer import Wappalyzer, WebPage
        
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)
        
        waf_list = []
        for tech in technologies:
            tech_name = tech.get('name', '')
            categories = tech.get('categories', [])
            
            for cat in categories:
                cat_name = cat.get('name', '').lower()
                if 'waf' in cat_name or 'security' in cat_name or 'firewall' in cat_name:
                    if tech_name not in waf_list:
                        waf_list.append(tech_name)
                    break
        
        return {"waf_names": waf_list, "detected": len(waf_list) > 0}
    except Exception as e:
        print(f"[Wappalyzer WAF] Error: {e}")
        return {"waf_names": [], "detected": False}

def detect_firewall(url: str) -> FirewallResult:
    """WAF/Firewall Detect করে"""
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )

        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        server_value = resp_headers.get("server", "").lower()
        
        detected_waf = None
        evidence_list = []

        # ── 1. Header based detection ──
        waf_signatures = {
            "cloudflare": {"name": "Cloudflare", "headers": ["cf-ray", "cf-cache-status", "cf-polished"]},
            "aws-waf": {"name": "AWS WAF", "headers": ["x-amzn-waf-action", "x-amz-cf-id"]},
            "sucuri": {"name": "Sucuri", "headers": ["x-sucuri-id", "x-sucuri-cache"]},
            "akamai": {"name": "Akamai", "headers": ["x-akamai-request-id"]},
            "imperva": {"name": "Imperva", "headers": ["x-iinfo", "x-incap-ses"]},
            "fastly": {"name": "Fastly", "headers": ["x-fastly-request-id", "x-served-by"]},
            "google-cloud-armor": {"name": "Google Cloud Armor", "headers": ["x-gfe-frontend"]}
        }
        
        for waf_key, waf_info in waf_signatures.items():
            for header in waf_info["headers"]:
                if header in resp_headers:
                    detected_waf = waf_info["name"]
                    evidence_list.append(f"Header: {header}")
                    break
            if detected_waf:
                break

        # ── 2. Server header check ──
        if not detected_waf:
            server_patterns = {
                "cloudflare": "Cloudflare",
                "sucuri": "Sucuri",
                "akamai": "Akamai",
                "imperva": "Imperva",
                "fastly": "Fastly",
                "aws": "AWS",
                "gfe": "Google Cloud Armor"
            }
            for pattern, name in server_patterns.items():
                if pattern in server_value:
                    detected_waf = name
                    evidence_list.append(f"Server: {server_value}")
                    break

        # ── 3. Wappalyzer detection (if not found) ──
        if not detected_waf:
            wappalyzer_result = detect_waf_with_wappalyzer(url)
            if wappalyzer_result.get("detected"):
                waf_names = wappalyzer_result.get("waf_names", [])
                if waf_names:
                    detected_waf = ", ".join(waf_names)
                    evidence_list.append("Wappalyzer detection")

        if detected_waf:
            return FirewallResult(
                url=url,
                detected=True,
                firewall_name=detected_waf,
                evidence="; ".join(evidence_list) if evidence_list else "WAF detected"
            )
        else:
            return FirewallResult(
                url=url,
                detected=False,
                firewall_name=None,
                evidence="No WAF/Firewall detected"
            )
        
    except Exception as e:
        print(f"[Firewall Detection] Error: {e}")
        return FirewallResult(url=url, error=str(e))
