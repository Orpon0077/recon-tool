# ── Firewall/WAF Detection Module (Fast Mode) ──────────────
import requests
import subprocess
import re
import time
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import FirewallResult

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
    """Fast WAF detection - headers first, wafw00f only if needed"""
    
    start_time = time.time()
    detected_waf = None
    evidence_list = []
    sources = []
    
    # ── 1. Headers Detection (Always fast) ──
    try:
        print("[Firewall] Checking headers...")
        response = requests.get(
            url,
            timeout=10,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        server_value = resp_headers.get("server", "").lower()
        
        for header, waf_name in WAF_HEADERS.items():
            if header in resp_headers:
                detected_waf = waf_name
                evidence_list.append(f"Header: {header}")
                sources.append("headers")
                print(f"[Firewall] Found: {detected_waf} (header)")
                break
        
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
                    print(f"[Firewall] Found: {detected_waf} (server)")
                    break
    except Exception as e:
        print(f"[Firewall] Header error: {e}")
    
    # ── 2. wafw00f (only if headers didn't detect) ──
    if not detected_waf:
        try:
            print("[Firewall] Running wafw00f (15s timeout)...")
            result = subprocess.run(
                f"wafw00f {url}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            output = result.stdout + result.stderr
            
            patterns = [
                r"The site (.+) is behind (.+)",
                r"WAF Detected: (.+)",
                r"Detected WAF: (.+)",
                r"is behind (.+)",
                r"WAF: (.+)",
            ]
            
            for pattern in patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    waf_name = match.group(1).strip()
                    waf_name = re.sub(r'[^a-zA-Z0-9\s\-\.]', '', waf_name)
                    if waf_name and waf_name.lower() not in ['none', 'unknown', '']:
                        detected_waf = waf_name
                        evidence_list.append("wafw00f")
                        sources.append("wafw00f")
                        print(f"[Firewall] Found: {detected_waf} (wafw00f)")
                        break
        except subprocess.TimeoutExpired:
            print("[Firewall] wafw00f timeout")
        except Exception as e:
            print(f"[Firewall] wafw00f error: {e}")
    
    # ── 3. Wappalyzer (skip if already found) ──
    if not detected_waf:
        try:
            print("[Firewall] Quick Wappalyzer...")
            from wappalyzer import Wappalyzer
            wappalyzer = Wappalyzer()
            results = wappalyzer.analyze(url)
            for tech_name in results:
                if 'waf' in tech_name.lower() or 'cloudflare' in tech_name.lower():
                    detected_waf = tech_name
                    evidence_list.append("Wappalyzer")
                    sources.append("wappalyzer")
                    print(f"[Firewall] Found: {detected_waf} (Wappalyzer)")
                    break
        except Exception as e:
            print(f"[Firewall] Wappalyzer skip: {e}")
    
    elapsed = time.time() - start_time
    print(f"[Firewall] Done in {elapsed:.1f}s")
    
    if detected_waf:
        return FirewallResult(
            url=url,
            detected=True,
            firewall_name=detected_waf,
            evidence=f"by: {', '.join(sources)}; {'; '.join(evidence_list)}"
        )
    else:
        return FirewallResult(
            url=url,
            detected=False,
            firewall_name=None,
            evidence="No WAF detected"
        )
