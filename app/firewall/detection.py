import requests
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import FirewallResult

WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-amzn-waf-action": "AWS WAF",
    "x-akamai-request-id": "Akamai",
    "x-iinfo": "Imperva",
    "x-fastly-request-id": "Fastly",
}

def detect_firewall(url: str) -> FirewallResult:
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        
        for header, waf_name in WAF_HEADERS.items():
            if header in resp_headers:
                return FirewallResult(url=url, detected=True, firewall_name=waf_name, evidence=f"Header: {header}")
        
        server = resp_headers.get("server", "").lower()
        server_wafs = {"cloudflare": "Cloudflare", "sucuri": "Sucuri", "akamai": "Akamai", "imperva": "Imperva", "fastly": "Fastly", "gfe": "Google Cloud Armor", "aws": "AWS", "cloudfront": "AWS CloudFront"}
        for pattern, name in server_wafs.items():
            if pattern in server:
                return FirewallResult(url=url, detected=True, firewall_name=name, evidence=f"Server: {server}")
        
        return FirewallResult(url=url, detected=False, firewall_name=None, evidence="No WAF detected")
    except Exception as e:
        return FirewallResult(url=url, error=str(e))
