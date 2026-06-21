# ── Security Headers Analysis Module ──────────────────────
# this module checks for the presence of important security headers in the HTTP response and calculates a security score based on how many of those headers are present. It also handles various exceptions that may occur during the request process.

import requests
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS     #Set request timeout and user agent header from config.py
from app.models import SecurityHeadersResult                #Import SecurityHeadersResult model to store the results of the security headers analysis

# the headers that should be present in a secure website
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
        # send a GET request to the website with the specified timeout and headers
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT, #Request timeout set from config.py
            headers=REQUEST_HEADERS, #User agent set from config.py
            allow_redirects=True, # redirects allowed to follow, so we can analyze the final destination's headers
        )

        # lowercase the response headers for easier comparison
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        present = {} # received security headers
        missing = [] # missing security headers

        # check each important header
        for header, description in IMPORTANT_HEADERS.items():
            if header in resp_headers:
                present[header] = resp_headers[header]
            else:
                missing.append(header)

        # calculate security score based on found and missing headers
        total = len(IMPORTANT_HEADERS) # total important headers
        found = len(present) # received headers
        score = int((found / total) * 100) # security score (0-100)

        return SecurityHeadersResult(
            url=url,                    # website URL
            present=present,            # received headers
            missing=missing,           # missing headers
            score=score,           # security score (0-100)
        )

    except requests.exceptions.ConnectionError:
        return SecurityHeadersResult(url=url, error="Connection failed") # this error occurs when the website is down or not reachable
    except requests.exceptions.Timeout:
        return SecurityHeadersResult(url=url, error="Request timed out") # this error occurs when the request times out
    except requests.exceptions.RequestException as e:               
        return SecurityHeadersResult(url=url, error=str(e)) # this error occurs for any other request-related issues