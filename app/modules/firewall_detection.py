# ── Firewall/WAF Detection Module ──────────────────────────
# Merges: Headers + Wappalyzer + wafw00f

import requests
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import FirewallResult
from app.modules.wafw00f_detection import detect_with_wafw00f

# ── WAF Headers Signatures ──
WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-amzn-waf-action": "AWS WAF",
    "x-amz-cf-id": "AWS CloudFront",
    "x-akamai-request-id": "Akamai",
    "x-iinfo": "Imperva",
    "x-incap-ses": "Imperva Incapsula",
    "x-fastly-request-id": "Fastly",
    "x-served-by": "Fastly",
    "x-gfe-frontend": "Google Cloud Armor"
}

def detect_firewall(url: str) -> FirewallResult:
    """Detect WAF using multiple sources and merge results"""
    
    detected_waf = None
    evidence_list = []
    sources = []
    
    # ── 1. Header Detection ──
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        server_value = resp_headers.get("server", "").lower()
        
        # Check headers
        for header, waf_name in WAF_HEADERS.items():
            if header in resp_headers:
                detected_waf = waf_name
                evidence_list.append(f"Header: {header}")
                sources.append("headers")
                break
        
        # Check server header
        if not detected_waf:
            server_wafs = {
                "cloudflare": "Cloudflare",
                "sucuri": "Sucuri",
                "akamai": "Akamai",
                "imperva": "Imperva",
                "fastly": "Fastly",
                "gfe": "Google Cloud Armor",
                "aws": "AWS",
                "cloudfront": "AWS CloudFront"
            }
            for pattern, name in server_wafs.items():
                if pattern in server_value:
                    detected_waf = name
                    evidence_list.append(f"Server: {server_value}")
                    sources.append("server")
                    break
    except Exception as e:
        print(f"[Firewall] Header detection error: {e}")
    
    # ── 2. wafw00f Detection ──
    if not detected_waf:
        print("[Firewall] Running wafw00f...")
        wafw00f_result = detect_with_wafw00f(url)
        if wafw00f_result.get("detected"):
            detected_waf = wafw00f_result.get("firewall_name")
            evidence_list.append("wafw00f")
            sources.append("wafw00f")
            print(f"[Firewall] wafw00f found: {detected_waf}")
    
    # ── 3. Wappalyzer Detection (if available) ──
    if not detected_waf:
        try:
            from wappalyzer import Wappalyzer
            wappalyzer = Wappalyzer()
            results = wappalyzer.analyze(url)
            
            for tech_name, tech_data in results.items():
                if 'waf' in tech_name.lower() or 'cloudflare' in tech_name.lower():
                    detected_waf = tech_name
                    evidence_list.append("Wappalyzer")
                    sources.append("wappalyzer")
                    break
        except Exception as e:
            print(f"[Firewall] Wappalyzer error: {e}")
    
    # ── Return Merged Result ──
    if detected_waf:
        return FirewallResult(
            url=url,
            detected=True,
            firewall_name=detected_waf,
            evidence=f"Detected by: {', '.join(sources)}; Evidence: {'; '.join(evidence_list)}"
        )
    else:
        return FirewallResult(
            url=url,
            detected=False,
            firewall_name=None,
            evidence="No WAF detected by headers, wafw00f, or Wappalyzer"
        )
