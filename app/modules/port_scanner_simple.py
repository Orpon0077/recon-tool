# ── Simple Port Scanner (Socket Based) ─────────────────────
import socket
from app.config import TOP_10_PORTS, TOP_50_PORTS, TOP_100_PORTS
from app.models import PortScanResult, PortInfo

def get_port_list(port_option: str, custom_ports: str = None) -> dict:
    if port_option == "top10":
        return TOP_10_PORTS
    elif port_option == "top50":
        return TOP_50_PORTS
    elif port_option == "top100":
        return TOP_100_PORTS
    elif port_option == "top1000":
        ports = {}
        for i in range(1, 1001):
            ports[i] = "unknown"
        return ports
    elif port_option == "all":
        ports = {}
        for i in range(1, 65536):
            ports[i] = "unknown"
        return ports
    elif port_option == "custom" and custom_ports:
        custom_dict = {}
        for p in custom_ports.split(","):
            p = p.strip()
            if p.isdigit():
                custom_dict[int(p)] = "Custom"
        return custom_dict
    else:
        return TOP_50_PORTS

def scan_port(host: str, port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_ports(url: str, port_option: str = "top50", custom_ports: str = None) -> PortScanResult:
    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(host)
        ports_to_scan = get_port_list(port_option, custom_ports)
        
        open_ports = []
        for port, service_name in ports_to_scan.items():
            if scan_port(ip, port):
                open_ports.append(PortInfo(
                    port=port,
                    service=service_name,
                    version="Version detection requires Nmap",
                    state="open",
                ))
        
        return PortScanResult(
            url=url,
            host=ip,
            open_ports=open_ports,
            total_open=len(open_ports),
            vulnerabilities=[],
            os_info={},
        )
    except socket.gaierror:
        return PortScanResult(url=url, host="", error="Hostname resolve failed")
    except Exception as e:
        return PortScanResult(url=url, host="", error=str(e))
