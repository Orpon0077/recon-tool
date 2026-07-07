import requests
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def fetch_js_content(js_url: str, timeout: int = 8) -> tuple:
    """Fetch a single JS file content with timeout. Returns (url, content) or (url, None)."""
    try:
        response = requests.get(js_url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            return js_url, response.text[:100000]  # Limit to 100KB
        else:
            return js_url, None
    except Exception:
        return js_url, None

def scan_javascript(url: str) -> dict:
    """
    Scan JavaScript files for emails, API endpoints, internal paths, etc.
    Fetches up to 20 JS files in parallel.
    """
    url = normalize_url(url)
    start_time = time.time()
    max_total_time = 55  # seconds – leave room for the 60s timeout

    try:
        response = requests.get(url, timeout=10)
        html = response.text
    except Exception as e:
        return {"error": str(e), "total_js_files": 0}

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
            if full_url not in js_files and len(js_files) < 30:  # Collect up to 30, but we'll only scan 20
                js_files.append(full_url)

    # Limit to 20 JS files
    js_files_to_scan = js_files[:20]

    # Fetch JS files in parallel using ThreadPoolExecutor
    js_contents = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_js_content, js_url, 8): js_url for js_url in js_files_to_scan}
        for future in as_completed(futures):
            # Stop if we're approaching the total timeout
            if time.time() - start_time > max_total_time:
                break
            js_url, content = future.result(timeout=10)
            if content:
                js_contents.append((js_url, content))

    # Extract patterns from each JS file
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    api_pattern = r'["\'](/api/[^\s"\']+)["\']'
    path_pattern = r'["\'](/(?:[a-zA-Z0-9_\-]+/?)+)["\']'
    token_pattern = r'(?:api[_-]?key|token|secret|access[_-]?token)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']'
    
    emails = []
    internal_paths = []
    api_endpoints = []
    tokens = []

    for js_url, content in js_contents:
        emails.extend(re.findall(email_pattern, content, re.IGNORECASE))
        api_endpoints.extend(re.findall(api_pattern, content))
        internal_paths.extend(re.findall(path_pattern, content))
        tokens.extend(re.findall(token_pattern, content, re.IGNORECASE))

    # Deduplicate and limit
    emails = list(set(emails))[:10]
    internal_paths = [p for p in set(internal_paths) if len(p) > 3 and not p.startswith(('/_', '/static', '/assets', '/css', '/js'))][:20]
    api_endpoints = list(set(api_endpoints))[:15]
    tokens = list(set(tokens))[:5]

    return {
        "total_js_files": len(js_files),
        "js_files": [{"url": u} for u in js_files[:10]],
        "emails": emails,
        "internal_paths": internal_paths,
        "api_endpoints": api_endpoints,
        "tokens": tokens,
        "social_media": []
    }