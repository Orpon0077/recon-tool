import socket
from app.models import PortInfo, PortScanResult

COMMON_PORTS = {80: "HTTP", 443: "HTTPS"}

def scan_ports(url: str, port_option: str = "top1000", custom_ports: str = None) -> PortScanResult:
    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(host)
        except:
            ip = host
        
        open_ports = []
        for port, service in COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(PortInfo(port=port, service=service, version="open", state="open"))
                sock.close()
            except:
                continue
        
        return PortScanResult(url=url, host=host, open_ports=open_ports, total_open=len(open_ports))
    except Exception as e:
        return PortScanResult(url=url, host="", error=str(e))
