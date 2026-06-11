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

SCREENSHOT_VIEWPORT = {"width": 1280, "height": 800}
SCREENSHOT_TIMEOUT_MS = 30_000

API_TITLE = "Recon Tool"
API_VERSION = "1.0.0"
API_DESCRIPTION = "Web Reconnaissance Tool"

# ── Port Lists ─────────────────────────────────────────────
# User যে option choose করবে সেই অনুযায়ী ports scan হবে

TOP_10_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

TOP_50_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2181: "Zookeeper", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Node/React", 3306: "MySQL", 3389: "RDP", 4200: "Angular",
    4369: "RabbitMQ", 5000: "Flask/Dev", 5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes", 7474: "Neo4j", 8000: "Dev Server", 8080: "HTTP-Alt",
    8081: "HTTP-Alt2", 8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM", 9042: "Cassandra",
    9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached",
    15672: "RabbitMQ-UI", 27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-Web",
    50070: "Hadoop", 50075: "Hadoop",
}

TOP_100_PORTS = {
    **TOP_50_PORTS,
    1: "TCPMUX", 7: "Echo", 9: "Discard", 13: "Daytime", 17: "QOTD",
    19: "Chargen", 20: "FTP-Data", 26: "RSFTP", 37: "Time", 49: "TACACS",
    69: "TFTP", 70: "Gopher", 79: "Finger", 81: "HTTP-Alt", 82: "HTTP-Alt",
    83: "HTTP-Alt", 84: "HTTP-Alt", 85: "HTTP-Alt", 88: "Kerberos", 89: "SU-MIT",
    99: "Metagram", 100: "NewActn", 106: "POP3PW", 109: "POP2", 113: "IDENT",
    119: "NNTP", 125: "Locus-MAP", 144: "NeWS", 146: "ISO-TP0", 161: "SNMP",
    163: "CMIP-Agent", 179: "BGP", 194: "IRC", 199: "SMUX", 211: "914C-G",
    212: "ATACS", 222: "RSH", 264: "BGMP", 308: "Novas-LM", 366: "ODMR",
    389: "LDAP", 406: "IMP-Remote", 408: "PRMSCommunication", 465: "SMTPS",
    481: "Ph", 497: "Retrospect", 500: "ISAKMP", 512: "Exec", 513: "Login",
}