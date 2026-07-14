import requests
from typing import Dict, List
from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def analyze_headers(url: str) -> Dict:
    """
    মূল ফাংশন – সিকিউরিটি হেডার বিশ্লেষণ করে dict রিটার্ন করে।
    এটি `llm.py` থেকে কল হয়।
    """
    return analyze_security_headers(url)

def analyze_security_headers(url: str) -> Dict:
    """
    ফ্রন্টএন্ডের renderSecurity()-এর জন্য ফরম্যাটে ডেটা রিটার্ন করে:
    { "score": int, "present": {header: value}, "missing": [header, ...] }
    """
    try:
        url = normalize_url(url)
        response = requests.get(url, timeout=30, allow_redirects=True)  # ← timeout 30
        headers = {k.lower(): v for k, v in response.headers.items()}

        important_headers = {
            "strict-transport-security": "Always use HTTPS",
            "content-security-policy": "Protects against XSS",
            "x-content-type-options": "MIME sniffing prevention",
            "x-frame-options": "Clickjacking prevention",
            "referrer-policy": "Referrer information control",
            "permissions-policy": "Browser features control",
        }

        present = {}
        missing = []

        for header, desc in important_headers.items():
            if header in headers:
                present[header] = headers[header]
            else:
                missing.append(header)

        total = len(important_headers)
        found = len(present)
        score = int((found / total) * 100) if total > 0 else 0

        return {
            "score": score,
            "present": present,
            "missing": missing,
        }

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}