# ── Security Headers Analysis Module ──────────────────────
# Website এর security headers check করে
# কোনগুলো আছে, কোনগুলো নেই, এবং score দেয়

import requests
from app.config import REQUEST_TIMEOUT, REQUEST_HEADERS     #Request timeout এবং User agent সেট করা
from app.models import SecurityHeadersResult                #SecurityHeadersResult মডেল ইম্পোর্ট করা

# যে headers গুলো একটা secure website এ থাকা উচিত
IMPORTANT_HEADERS = {
    "strict-transport-security": "সবসময় HTTPS use করো",
    "content-security-policy": "XSS attack থেকে রক্ষা করে",
    "x-content-type-options": "MIME sniffing থেকে রক্ষা করে",
    "x-frame-options": "Clickjacking থেকে রক্ষা করে",
    "referrer-policy": "Referrer information control করে",
    "permissions-policy": "Browser features control করে",
}

def analyze_security_headers(url: str) -> SecurityHeadersResult:
    try:
        #website এ request পাঠিয়ে response header পাওয়া
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT, #Request timeout সেট করা
            headers=REQUEST_HEADERS, #User agent সহ request পাঠানো
            allow_redirects=True, # redirect হলে ও analyze করবে
        )

        # সব response headers lowercase করো
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        present = {} # পাওয়া security headers
        missing = [] # অনুপস্থিত security headers

        # প্রতিটা important header check করো
        for header, description in IMPORTANT_HEADERS.items():
            if header in resp_headers:
                present[header] = resp_headers[header]
            else:
                missing.append(header)

        # score হিসাব করা (প্রতিটা পাওয়া header এর জন্য 100/total_headers)
        total = len(IMPORTANT_HEADERS) # মোট important headers
        found = len(present) # পাওয়া headers
        score = int((found / total) * 100) # security score (0-100)

        return SecurityHeadersResult(
            url=url,                    # URL সেট করা
            present=present,            # পাওয়া headers
            missing=missing,           # অনুপস্থিত headers
            score=score,           # security score সেট করা
        )

    except requests.exceptions.ConnectionError:
        return SecurityHeadersResult(url=url, error="Connection failed") #Connection error হলে এখানে message আসবে
    except requests.exceptions.Timeout:
        return SecurityHeadersResult(url=url, error="Request timed out") #Request timeout হলে এখানে message আসবে
    except requests.exceptions.RequestException as e:               
        return SecurityHeadersResult(url=url, error=str(e)) # অন্য কোনো request error হলে সেটার message এখানে আসবে

