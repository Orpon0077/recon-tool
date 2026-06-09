# ── Firewall Detection Module ──────────────────────────────
# Website এ WAF/Firewall আছে কিনা detect করে

import requests
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import FirewallResult


# Header দেখে firewall detect করার rules
# key = header নাম, value = (firewall নাম, evidence message)
FIREWALL_HEADERS = {
    "cf-ray": ("Cloudflare", "CF-Ray header found"),
    "cf-cache-status": ("Cloudflare", "CF-Cache-Status header found"),
    "x-sucuri-id": ("Sucuri", "X-Sucuri-ID header found"),
    "x-sucuri-cache":  ("Sucuri", "x-sucuri-cache header found"),
    "x-firewall-protection":     ("Generic WAF",     "x-firewall-protection header found"),
    "x-waf-event-info":          ("Generic WAF",     "x-waf-event-info header found"),
    "x-amzn-waf-action":         ("AWS WAF",         "x-amzn-waf-action header found"),
    "x-amzn-requestid":          ("AWS",             "x-amzn-requestid header found"),
    "x-akamai-request-id":       ("Akamai",          "x-akamai-request-id header found"),
    "x-cdn":                     ("CDN/WAF",         "x-cdn header found"),
    "x-imperva-id":              ("Imperva",         "x-imperva-id header found"),
    "x-incap-ses":               ("Imperva Incapsula","x-incap-ses header found"),
    "x-iinfo":                   ("Imperva Incapsula","x-iinfo header found"),
}

# Server header এর value দেখে firewall detect করার rules
SERVER_SIGNATURES   = {
    "cloudflare":   "Cloudflare",
    "sucuri":       "Sucuri",
    "akamai":       "Akamai",
    "imperva":      "Imperva",
    "aws":          "AWS WAF",
    "barracuda":    "Barracuda WAF",
    "f5":           "F5 BIG-IP",
    "fortinet":     "Fortinet FortiWeb",

}

def detect_firewall(url: str) -> FirewallResult:
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers=REQUEST_HEADERS,
            allow_redirects=True,
        )

        # সব headers lowercase করো
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # ── Step 1: Header দেখে detect করো ──────────────────
        for header, (firewall_name, evidence) in FIREWALL_HEADERS.items():
            if header in resp_headers:
                return FirewallResult(
                    url=url,
                    detected=True,
                    firewall_name=firewall_name,
                    evidence=evidence
                )

        # ── Step 2: Server header এর value দেখে detect করো ──
        server_value = resp_headers.get("server", "").lower()
        for signature, firewall_name in SERVER_SIGNATURES.items():
            if signature in server_value:
                return FirewallResult(
                    url=url,
                    detected=True,
                    firewall_name=firewall_name,
                    evidence=f"Server header contains '{signature}'"
                )

            # ── Step 3: কিছু পাওয়া যায়নি ────────────────────────
        return FirewallResult(
            url=url,
            detected=False,
            firewall_name=None,
            evidence="No WAF/Firewall indicators found in headers"
        )
    except requests.exceptions.ConnectionError:
        return FirewallResult(url=url, error="Connection failed")
    except requests.exceptions.Timeout:
        return FirewallResult(url=url, error="Request timed out")
    except requests.exceptions.RequestException as e:
        return FirewallResult(url=url, error=str(e))
            