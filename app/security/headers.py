import requests
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS
from app.models import SecurityHeadersResult

IMPORTANT_HEADERS = {
    "strict-transport-security": "Always use HTTPS",
    "content-security-policy": "Protects against XSS attacks",
    "x-content-type-options": "MIME sniffing prevention",
    "x-frame-options": "Clickjacking prevention",
    "referrer-policy": "Referrer information control",
    "permissions-policy": "Browser features control",
}

def analyze_security_headers(url: str) -> SecurityHeadersResult:
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        present = {}
        missing = []

        for header, description in IMPORTANT_HEADERS.items():
            if header in resp_headers:
                present[header] = resp_headers[header]
            else:
                missing.append(header)

        total = len(IMPORTANT_HEADERS)
        found = len(present)
        score = int((found / total) * 100)

        return SecurityHeadersResult(url=url, present=present, missing=missing, score=score)
    except Exception as e:
        return SecurityHeadersResult(url=url, error=str(e))
