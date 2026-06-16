# ── Port Scanner Module with Nmap ──────────────────────────
import subprocess
import socket
from app.config import TOP_10_PORTS, TOP_50_PORTS, TOP_100_PORTS
from app.models import PortScanResult, PortInfo

def get_port_list(port_option: str, custom_ports: str = None) -> list:
    if port_option == "top10":
        return list(TOP_10_PORTS.keys())
    elif port_option == "top50":
        return list(TOP_50_PORTS.keys())
    elif port_option == "top100":
        return list(TOP_100_PORTS.keys())
    elif port_option == "top1000":
        return list(range(1, 1001))
    elif port_option == "all":
        return []
    elif port_option == "custom" and custom_ports:
        return [int(p.strip()) for p in custom_ports.split(",") if p.strip().isdigit()]
    else:
        return list(TOP_50_PORTS.keys())

def scan_ports(url: str, port_option: str = "top50", custom_ports: str = None) -> PortScanResult:
    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip = socket.gethostbyname(host)
        except:
            ip = host
        
        ports = get_port_list(port_option, custom_ports) 
        
        if not ports:
            port_arg = "1-1000"
        else:
            port_arg = ",".join(str(p) for p in ports[:500])
        
        # Run nmap without OS detection for speed
        cmd = f"nmap -sV -T4 {ip} -p {port_arg}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        open_ports = []
        
        # Parse nmap output
        lines = result.stdout.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_str = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = ' '.join(parts[3:]) if len(parts) > 3 else 'Service detected'
                    
                    open_ports.append(PortInfo(
                        port=int(port_str),
                        service=service,
                        version=version[:100],
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
        
    except Exception as e:
        return PortScanResult(url=url, host="", error=str(e))
