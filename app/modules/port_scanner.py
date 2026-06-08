# ── Port Scanner Module ────────────────────────────────────
# Website এর open ports এবং service version বের করে

import socket
from app.models import PortScanResult, PortInfo

# সবচেয়ে common ports এবং তাদের service নাম
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",                   
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def get_service_version(host: str, port: int) -> str:
    """
    Port এ connect করে service এর banner পড়ে।
    Banner = service যে পরিচয় দেয় connect হওয়ার পর।
    """
    try:
        # Port এ connect করো
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))

        # Service কী বলে সেটা পড়ো
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        # প্রথম line নাও — সেটাই version info
        first_line = banner.split("\n")[0].strip()
        return first_line if first_line else "Unknown"

    except Exception:
        return "Unknown"


def scan_port(host: str, port: int) -> bool:
    """
    একটা port open আছে কিনা check করে।
    Open থাকলে True, বন্ধ থাকলে False।
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # ১ সেকেন্ড অপেক্ষা করো
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0  # 0 মানে সফলভাবে connect হয়েছে
    except Exception:
        return False


def scan_ports(url: str) -> PortScanResult:
    try:
        # URL থেকে hostname বের করো
        host = url.replace("https://", "").replace("http://", "").split("/")[0]

        # hostname কে IP তে convert করো
        ip = socket.gethostbyname(host)

        open_ports = []

        # প্রতিটা common port check করো
        for port, service_name in COMMON_PORTS.items():
            if scan_port(ip, port):
                # Port open — version জানার চেষ্টা করো
                version = get_service_version(ip, port)

                open_ports.append(PortInfo(
                    port=port,
                    service=service_name,
                    version=version,
                    state="open",
                ))

        return PortScanResult(
            url=url,
            host=host,
            open_ports=open_ports,
            total_open=len(open_ports),
        )

    except socket.gaierror:
        return PortScanResult(url=url, error="Hostname resolve করা যায়নি")
    except Exception as e:
        return PortScanResult(url=url, error=str(e))