# ── Modules Package ────────────────────────────────────────
# all modules are imported here to make them accessible when the package is imported

# ── SSL/TLS Analysis ───────────────────────────────────────
from .ssl_analysis import analyze_ssl

# ── Security Headers Analysis ──────────────────────────────
from .security_headers import analyze_security_headers

# ── Port Scanning ──────────────────────────────────────────
from .port_scanner import scan_ports

# ── Screenshot ─────────────────────────────────────────────
from .screenshot import capture_screenshot

# ── Firewall Detection ─────────────────────────────────────
from .firewall_detection import detect_firewall

# ── Tech Detection ─────────────────────────────────────────
from .tech_detection import detect_technologies

# ── Crawling ───────────────────────────────────────────────
from .crawler import crawl_website

# ── JS Scanner ─────────────────────────────────────────────
from .js_scanner import scan_javascript

# ── Subdomain Discovery ────────────────────────────────────
from .subdomain_discovery import discover_subdomains

__all__ = [
    "analyze_ssl",
    "analyze_security_headers",
    "scan_ports",
    "capture_screenshot",
    "detect_firewall",
    "detect_technologies",
    "crawl_website",
    "scan_javascript",
    "discover_subdomains"
]
