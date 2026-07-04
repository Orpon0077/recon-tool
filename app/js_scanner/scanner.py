import requests
import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def scan_javascript(url: str) -> Dict:
    """
    Returns format expected by frontend renderJSScanner():
    {
        "total_js_files": int,
        "js_files": [{"url": str}],
        "emails": [str],
        "internal_paths": [str],
        "api_endpoints": [str],
        "tokens": [str],
        "social_media": [str]
    }
    """
    try:
        url = normalize_url(url)
        response = requests.get(url, timeout=10)
        html = response.text

        # Find JS files
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'src=["\']([^"\']+\.js[^"\']*)["\']',
        ]
        js_files = []
        for pattern in js_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(url, match)
                if full_url not in js_files:
                    js_files.append(full_url)

        # Fetch first 10 JS files and extract info
        emails = []
        internal_paths = []
        api_endpoints = []
        tokens = []
        social_media = []

        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        api_pattern = r'["\'](/api/[^\s"\']+)["\']'
        path_pattern = r'["\'](/(?:[a-zA-Z0-9_\-]+/?)+)["\']'
        token_pattern = r'(?:api[_-]?key|token|secret|access[_-]?token)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']'

        social_patterns = {
            'facebook': r'facebook\.com/([a-zA-Z0-9.]+)',
            'twitter': r'twitter\.com/([a-zA-Z0-9_]+)',
            'linkedin': r'linkedin\.com/(?:company|in)/([a-zA-Z0-9_-]+)',
            'instagram': r'instagram\.com/([a-zA-Z0-9_.]+)',
            'github': r'github\.com/([a-zA-Z0-9_-]+)',
        }

        for js_url in js_files[:10]:
            try:
                js_resp = requests.get(js_url, timeout=5)
                content = js_resp.text[:100000]

                emails.extend(re.findall(email_pattern, content, re.IGNORECASE))
                api_endpoints.extend(re.findall(api_pattern, content))
                internal_paths.extend(re.findall(path_pattern, content))
                tokens.extend(re.findall(token_pattern, content, re.IGNORECASE))

                for platform, pattern in social_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        social_media.append(f"{platform}: {match}")

            except:
                continue

        # Deduplicate and limit
        emails = list(set(emails))[:10]
        internal_paths = [p for p in set(internal_paths) if len(p) > 3 and not p.startswith(('/_', '/static', '/assets', '/css', '/js'))][:20]
        api_endpoints = list(set(api_endpoints))[:15]
        tokens = list(set(tokens))[:5]
        social_media = list(set(social_media))[:5]

        return {
            "total_js_files": len(js_files),
            "js_files": [{"url": u} for u in js_files[:10]],
            "emails": emails,
            "internal_paths": internal_paths,
            "api_endpoints": api_endpoints,
            "tokens": tokens,
            "social_media": social_media,
        }

    except Exception as e:
        return {
            "error": str(e),
            "total_js_files": 0,
            "js_files": [],
            "emails": [],
            "internal_paths": [],
            "api_endpoints": [],
            "tokens": [],
            "social_media": [],
        }