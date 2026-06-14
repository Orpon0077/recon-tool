# ── Port Scanner Module (Pure Socket - No External Tools) ───
import socket
from app.models import PortInfo, PortScanResult

# Most important web ports
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
}

def scan_ports(url: str, port_option: str = "top1000", custom_ports: str = None) -> PortScanResult:
    """Fast port scanning using Python socket"""
    try:
        # Extract host from URL
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Resolve IP
        try:
            ip = socket.gethostbyname(host)
        except:
            ip = host
        
        print(f"[PortScanner] Scanning {host} ({ip})...")
        
        open_ports = []
        
        # Always check common web ports
        for port, service in COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(PortInfo(
                        port=port,
                        service=service,
                        version="open",
                        state="open"
                    ))
                    print(f"[PortScanner] Found: {port}/{service}")
            except Exception as e:
                print(f"[PortScanner] Error on port {port}: {e}")
        
        print(f"[PortScanner] Total open: {len(open_ports)}")
        
        return PortScanResult(
            url=url,
            host=host,
            open_ports=open_ports,
            total_open=len(open_ports),
            vulnerabilities=[],
            os_info={},
        )
        
    except Exception as e:
        print(f"[PortScanner] Error: {e}")
        return PortScanResult(url=url, host="", error=str(e))
