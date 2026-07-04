import socket
from typing import Dict, List
from urllib.parse import urlparse

def scan_ports(url: str, port_option: str = "top1000", custom_ports: str = None) -> Dict:
    """
    Returns format expected by frontend renderPorts():
    { "total_open": int, "open_ports": [{"port": int, "service": str, "state": str, "version": str}], "os_info": {} }
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return {"error": "Invalid URL"}

        try:
            ip = socket.gethostbyname(host)
        except:
            ip = host

        common_ports = {80: "HTTP", 443: "HTTPS"}
        open_ports = []

        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "state": "open",
                        "version": "open",
                    })
                sock.close()
            except:
                continue

        return {
            "total_open": len(open_ports),
            "open_ports": open_ports,
            "os_info": {},  # no OS detection in simple scanner
        }

    except Exception as e:
        return {"error": str(e)}