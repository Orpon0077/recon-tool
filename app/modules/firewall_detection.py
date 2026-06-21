# ── Firewall Detection Module ──────────────────────────────
import requests
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import FirewallResult

FIREWALL_HEADERS = {
    "cf-ray": ("Cloudflare", "CF-Ray header found"),
    "cf-cache-status": ("Cloudflare", "CF-Cache-Status header found"),
    "x-sucuri-id": ("Sucuri", "X-Sucuri-ID header found"),
    "x-sucuri-cache": ("Sucuri", "X-Sucuri-Cache header found"),
    "x-amzn-waf-action": ("AWS WAF", "X-Amzn-Waf-Action header found"),
    "x-akamai-request-id": ("Akamai", "X-Akamai-Request-Id header found"),
    "x-imperva-id": ("Imperva", "X-Imperva-Id header found"),
    "x-incap-ses": ("Imperva Incapsula", "X-Incap-Ses header found"),
    "x-iinfo": ("Imperva Incapsula", "X-Iinfo header found"),
}

SERVER_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "sucuri": "Sucuri",
    "akamai": "Akamai",
    "imperva": "Imperva",
    "aws": "AWS WAF",
    "barracuda": "Barracuda WAF",
    "f5": "F5 BIG-IP",
    "fortinet": "Fortinet FortiWeb",
    "gws": "Google Frontend (GFE) / Google Cloud Armor",
    "google frontend": "Google Frontend (GFE) / Google Cloud Armor",
    "gfe": "Google Frontend (GFE) / Google Cloud Armor",
}

def detect_firewall(url: str) -> FirewallResult:
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )

        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        server_value = resp_headers.get("server", "").lower()

        # Header check
        for header, (firewall_name, evidence) in FIREWALL_HEADERS.items():
            if header in resp_headers:
                return FirewallResult(
                    url=url,
                    detected=True,
                    firewall_name=firewall_name,
                    evidence=evidence
                )

        # Server header check
        for signature, firewall_name in SERVER_SIGNATURES.items():
            if signature in server_value:
                return FirewallResult(
                    url=url,
                    detected=True,
                    firewall_name=firewall_name,
                    evidence=f"Server header contains '{signature}'"
                )

        # Google special detection
        if "gws" in server_value:
            return FirewallResult(
                url=url,
                detected=True,
                firewall_name="Google Cloud Armor / Google Frontend (GFE)",
                evidence="Server: gws - Google Frontend with Cloud Armor WAF"
            )

        return FirewallResult(
            url=url,
            detected=False,
            firewall_name=None,
            evidence="No WAF/Firewall indicators found"
        )
        
    except Exception as e:
        return FirewallResult(url=url, error=str(e))