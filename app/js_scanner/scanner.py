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

def fetch_js_content(js_url: str, timeout: int = 20) -> tuple:
    """Fetch a single JS file content with timeout. Returns (url, content) or (url, None)."""
    try:
        response = requests.get(js_url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code == 200:
            return js_url, response.text[:100000]  # Limit to 100KB
        else:
            return js_url, None
    except Exception:
        return js_url, None

# ── Fix #3: Denylist for Next.js internal strings and common false positives ──
NEXTJS_INTERNAL_PATTERNS = [
    r'__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE',
    r'__NEXT_DATA__',
    r'__NEXT_',
    r'next/dist',
    r'--next-',
    r'home-integrations__track--reverse',
    r'home-integrations__track--',
    r'__webpack_',
    r'__REACT_',
    r'__DEV__',
    r'__PROD__',
    r'__BROWSER__',
    r'__SERVER__',
    r'next/',
    r'next-',
    r'__NEXT_',
    r'__NEXT_',
    r'__NEXT_',
]

def is_nextjs_internal_string(text: str) -> bool:
    """Check if a string is a Next.js internal framework string that should be filtered out."""
    for pattern in NEXTJS_INTERNAL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def scan_javascript(url: str) -> dict:
    """
    Scan JavaScript files for emails, API endpoints, internal paths, tokens/secrets, source maps.
    Returns tokens with confidence and context.
    """
    url = normalize_url(url)
    start_time = time.time()
    max_total_time = 55

    try:
        response = requests.get(url, timeout=30)
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
            if full_url not in js_files and len(js_files) < 30:
                js_files.append(full_url)

    js_files_to_scan = js_files[:20]

    js_contents = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_js_content, js_url, 20): js_url for js_url in js_files_to_scan}
        for future in as_completed(futures):
            if time.time() - start_time > max_total_time:
                break
            js_url, content = future.result(timeout=15)
            if content:
                js_contents.append((js_url, content))

    # ── Pattern definitions ──
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    api_pattern = r'["\'](/api/[^\s"\']+)["\']'
    path_pattern = r'["\'](/(?:[a-zA-Z0-9_\-]+/?)+)["\']'

    # Token patterns with confidence weighting
    token_patterns = [
        {"pattern": r'AKIA[A-Z0-9]{16}', "confidence": "high", "type": "AWS Access Key"},
        {"pattern": r'sk-[a-zA-Z0-9]{24,}', "confidence": "high", "type": "OpenAI Key"},
        {"pattern": r'ghp_[a-zA-Z0-9]{36}', "confidence": "high", "type": "GitHub Token"},
        {"pattern": r"(?:api[_-]?key|token|secret|access[_-]?token)[\s]*[:=][\s]*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "confidence": "medium", "type": "Generic API Key"},
        {"pattern": r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----', "confidence": "high", "type": "Private Key"},
        {"pattern": r'[a-zA-Z0-9_-]{32,}', "confidence": "low", "type": "Potential Long Token"},
    ]
    sourcemap_pattern = r'//# sourceMappingURL=([^\s]+)'

    emails = []
    internal_paths = []
    api_endpoints = []
    tokens = []
    source_maps = []
    vulnerabilities = []

    for js_url, content in js_contents:
        emails.extend(re.findall(email_pattern, content, re.IGNORECASE))
        api_endpoints.extend(re.findall(api_pattern, content))

        # Filter internal paths (skip static assets)
        found_paths = re.findall(path_pattern, content)
        for p in found_paths:
            if len(p) > 3 and not p.startswith(('/_', '/static', '/assets', '/css', '/js')):
                internal_paths.append(p)

        # ── Fix #3: Token detection with denylist filter ──
        for token_def in token_patterns:
            matches = re.findall(token_def["pattern"], content, re.IGNORECASE)
            for match in matches:
                # For low confidence, filter out common false positives like paths or IDs
                if token_def["confidence"] == "low" and (match.startswith('/') or match.startswith('.')):
                    continue
                
                # ── Denylist check: skip Next.js internal strings ──
                if is_nextjs_internal_string(match):
                    continue
                
                # Extract context (30 chars before and after)
                try:
                    start_idx = content.find(match)
                    if start_idx != -1:
                        context_start = max(0, start_idx - 30)
                        context_end = min(len(content), start_idx + len(match) + 30)
                        context_snippet = content[context_start:context_end].replace('\n', ' ').strip()
                    else:
                        context_snippet = match
                except:
                    context_snippet = match

                tokens.append({
                    "value": match,
                    "type": token_def["type"],
                    "confidence": token_def["confidence"],
                    "context": context_snippet
                })

        # Source map detection
        sm = re.findall(sourcemap_pattern, content)
        if sm:
            source_maps.extend([{"url": js_url, "map": sm[0]}])

        # Basic vulnerability detection
        if 'eval(' in content or 'document.write(' in content:
            vulnerabilities.append({
                "file": js_url,
                "pattern": "Possible eval or document.write usage",
                "severity": "LOW"
            })

    # Deduplicate
    emails = list(set(emails))[:10]
    internal_paths = list(set(internal_paths))[:20]
    api_endpoints = list(set(api_endpoints))[:15]

    # Deduplicate tokens by value
    seen_tokens = set()
    unique_tokens = []
    for t in tokens:
        if t["value"] not in seen_tokens:
            seen_tokens.add(t["value"])
            unique_tokens.append(t)
    tokens = unique_tokens[:5]

    return {
        "total_js_files": len(js_files),
        "js_files": [{"url": u} for u in js_files[:10]],
        "emails": emails,
        "internal_paths": internal_paths,
        "api_endpoints": api_endpoints,
        "tokens": tokens,
        "source_maps": source_maps,
        "vulnerabilities": vulnerabilities,
        "social_media": []
    }