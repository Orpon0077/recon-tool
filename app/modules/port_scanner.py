# ── Port Scanner Module ────────────────────────────────────
# Website এর open ports, services এবং version detect করে

import socket
import requests
from app.models import PortScanResult, PortInfo

# Common ports এবং তাদের service নাম
COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# HTTP দিয়ে version বের করা যায় এমন ports
HTTP_PORTS = {80, 443, 8080, 8443}


def get_version_from_http(host: str, port: int) -> str:
    """
    HTTP request করে Server header থেকে version বের করে।
    যেমন: Server: Apache/2.4.51 → "Apache 2.4.51"
    """
    try:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{host}:{port}"

        response = requests.get(
            url,
            timeout=3,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=False,
        )

        # Server header থেকে version বের করো
        server = response.headers.get("Server", "")
        if server:
            return server

        # X-Powered-By header থেকেও দেখো
        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            return powered_by

        return f"HTTP {response.status_code}"

    except requests.exceptions.SSLError:
        return "SSL Error"
    except Exception:
        return "Unknown"


def get_version_from_banner(host: str, port: int) -> str:
    """
    TCP connection করে service banner পড়ে।
    SSH, FTP ইত্যাদি port এর জন্য।
    যেমন: SSH-2.0-OpenSSH_8.2p1
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))

        # কিছু services automatically banner পাঠায়
        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            # Banner না আসলে HTTP request পাঠাই
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        sock.close()

        # প্রথম line নাও
        first_line = banner.split("\n")[0].strip()
        return first_line if first_line else "Unknown"

    except Exception:
        return "Unknown"


def scan_port(host: str, port: int) -> bool:
    """
    একটা port open আছে কিনা check করে।
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(url: str) -> PortScanResult:
    try:
        # URL থেকে hostname বের করো
        host = url.replace("https://", "").replace("http://", "").split("/")[0]

        # Hostname কে IP তে convert করো
        ip = socket.gethostbyname(host)

        open_ports = []

        for port, service_name in COMMON_PORTS.items():
            if scan_port(ip, port):

                # ── Version detect করো ────────────────────
                if port in HTTP_PORTS:
                    # HTTP ports এ HTTP request করে version নাও
                    version = get_version_from_http(host, port)
                else:
                    # অন্য ports এ banner পড়ো
                    version = get_version_from_banner(ip, port)

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