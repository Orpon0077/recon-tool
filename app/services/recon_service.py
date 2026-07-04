import subprocess
import json
import uuid
import socket
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Optional

async def scan_ports(domain: str) -> Optional[Dict]:
    """Perform port scan on target domain"""
    try:
        scan_id = str(uuid.uuid4())
        print(f"[RECON_SERVICE] Starting port scan for {domain}")
        
        # Try nmap first
        try:
            open_ports = await scan_ports_nmap(domain)
            if open_ports:
                return {
                    "target": domain,
                    "open_ports": open_ports,
                    "scan_id": scan_id,
                    "timestamp": datetime.now().isoformat(),
                    "method": "nmap"
                }
        except Exception as e:
            print(f"[RECON_SERVICE] nmap failed, using python scanner: {e}")
        
        # Fallback to python scanner
        open_ports = await scan_ports_python(domain)
        
        return {
            "target": domain,
            "open_ports": open_ports,
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "method": "python"
        }
        
    except Exception as e:
        print(f"[RECON_SERVICE] Port scan error: {e}")
        return None

async def scan_ports_nmap(domain: str) -> List[Dict]:
    """Scan ports using nmap"""
    try:
        # Fast scan top 1000 ports
        cmd = f"nmap -T4 -F {domain} -oX -"
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=60
        )
        
        if result.returncode != 0:
            raise Exception("nmap failed")
        
        # Parse nmap output
        return parse_nmap_output(result.stdout)
        
    except subprocess.TimeoutExpired:
        raise Exception("nmap timeout")
    except FileNotFoundError:
        raise Exception("nmap not installed")

async def scan_ports_python(domain: str) -> List[Dict]:
    """Scan ports using Python socket (fallback)"""
    open_ports = []
    
    # Common ports to scan
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
        443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 
        6379, 8080, 8443, 27017
    ]
    
    print(f"[RECON_SERVICE] Scanning {len(common_ports)} common ports...")
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((domain, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    # Scan ports in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(scan_port, common_ports)
        for port, result in zip(common_ports, results):
            if result:
                open_ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "service": get_service_name(port)
                })
    
    return open_ports

def parse_nmap_output(xml_output: str) -> List[Dict]:
    """Parse nmap XML output"""
    import xml.etree.ElementTree as ET
    open_ports = []
    
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            for ports in host.findall('ports'):
                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        
                        open_ports.append({
                            "port": int(port_id),
                            "protocol": protocol,
                            "service": service_name
                        })
    except Exception as e:
        print(f"[RECON_SERVICE] Parse error: {e}")
    
    return open_ports

def get_service_name(port: int) -> str:
    """Get service name by port number"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
        135: "MS RPC", 139: "NetBIOS", 143: "IMAP", 
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1723: "PPTP", 3306: "MySQL", 3389: "RDP", 
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    return services.get(port, "unknown")

# For testing
if __name__ == "__main__":
    import asyncio
    result = asyncio.run(scan_ports("google.com"))
    print(json.dumps(result, indent=2))