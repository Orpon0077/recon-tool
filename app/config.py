from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
SCREENSHOTS_DIR = BASE_DIR / "static" / "screenshots"

SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

REQUEST_TIMEOUT = 10
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

MAX_CRAWL_LINKS = 100
SCREENSHOT_VIEWPORT = {"width": 1280, "height": 800}
SCREENSHOT_TIMEOUT_MS = 30_000

API_TITLE = "Web Reconnaissance Dashboard"
API_VERSION = "1.0.0"
API_DESCRIPTION = "Modular web reconnaissance API."

# ── Port Lists for Scanning ─────────────────────────────────
TOP_10_PORTS = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
    53: "DNS", 110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S"
}

TOP_50_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB"
}

TOP_100_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 42: "WINS",
    53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP",
    135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP-trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    636: "LDAPS", 873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1812: "RADIUS",
    2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 3074: "Xbox",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4000: "remote", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6667: "IRC", 8000: "HTTP-alt", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 27017: "MongoDB"
}
