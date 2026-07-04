# ── URL Utilities ───────────────────────────────────────────
def normalize_url(url: str) -> str:
    """Add https:// if missing"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    url = normalize_url(url)
    return url.replace('https://', '').replace('http://', '').split('/')[0]
