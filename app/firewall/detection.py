import requests
from typing import Dict
from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def detect_firewall(url: str) -> Dict:
    """
    Returns format expected by frontend renderFirewall():
    { "detected": bool, "firewall_name": str or None, "evidence": str }
    """
    try:
        url = normalize_url(url)
        response = requests.get(url, timeout=30, allow_redirects=True)  # ← timeout 30
        headers = {k.lower(): v for k, v in response.headers.items()}
        text = response.text.lower()

        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
            'AWS WAF': ['aws-waf', 'x-amzn-requestid'],
            'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            'ModSecurity': ['mod_security', 'x-modsecurity'],
            'Akamai': ['x-akamai', 'x-akamaitech'],
            'Fastly': ['x-fastly', 'fastly'],
            'CloudFront': ['x-amz-cf-id', 'cloudfront'],
            'Incapsula': ['x-iinfo', 'incapsula'],
            'Barracuda': ['x-barracuda', 'barracuda'],
            'Wordfence': ['wordfence', 'wf_'],
            'Shield': ['x-shield'],
        }

        headers_str = str(headers).lower()
        detected = []
        evidence = ""

        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in headers_str or sig in text:
                    detected.append(waf_name)
                    evidence = f"Found signature '{sig}'"
                    break
            if detected:
                break

        if detected:
            return {
                "detected": True,
                "firewall_name": detected[0],
                "evidence": evidence or "WAF signature detected",
            }
        else:
            return {
                "detected": False,
                "firewall_name": None,
                "evidence": "No WAF indicators found",
            }

    except requests.exceptions.Timeout:
        return {"error": "Connection timeout"}
    except Exception as e:
        return {"error": str(e)}