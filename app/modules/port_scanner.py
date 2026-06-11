# ── Port Scanner Module ────────────────────────────────────
import socket
import requests
from app.config import TOP_10_PORTS, TOP_50_PORTS, TOP_100_PORTS
from app.models import PortScanResult, PortInfo

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 3000, 4200, 5000, 8888}


def get_port_list(port_option: str, custom_ports: str = None) -> dict:
    if port_option == "top10":
        return TOP_10_PORTS
    elif port_option == "top50":
        return TOP_50_PORTS
    elif port_option == "top100":
        return TOP_100_PORTS
    elif port_option == "custom" and custom_ports:
        custom_dict = {}
        for p in custom_ports.split(","):
            p = p.strip()
            if p.isdigit():
                custom_dict[int(p)] = "Custom"
        return custom_dict
    else:
        return TOP_50_PORTS


def get_version_from_http(host: str, port: int) -> str:
    try:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{host}:{port}"
        response = requests.get(
            url, timeout=3, verify=False,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=False,
        )
        server = response.headers.get("Server", "")
        if server:
            return server
        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            return powered_by
        return f"HTTP {response.status_code}"
    except requests.exceptions.SSLError:
        return "SSL Error"
    except Exception:
        return "Unknown"


def get_version_from_banner(host: str, port: int) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        first_line = banner.split("\n")[0].strip()
        return first_line if first_line else "Unknown"
    except Exception:
        return "Unknown"


def scan_port(host: str, port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(url: str, port_option: str = "top50", custom_ports: str = None) -> PortScanResult:
    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(host)
        ports_to_scan = get_port_list(port_option, custom_ports)
        open_ports = []

        for port, service_name in ports_to_scan.items():
            if scan_port(ip, port):
                if port in HTTP_PORTS:
                    version = get_version_from_http(host, port)
                else:
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
        return PortScanResult(url=url, error="Hostname resolve failed")
    except Exception as e:
        return PortScanResult(url=url, error=str(e))