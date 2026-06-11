# ── Port Scanner Module (Auto-select) ──────────────────────
import subprocess
from app.models import PortScanResult

# Check if nmap is available
try:
    subprocess.run(["nmap", "--version"], capture_output=True, check=True)
    NMAP_AVAILABLE = True
except:
    NMAP_AVAILABLE = False

if NMAP_AVAILABLE:
    print("[PortScanner] Using Nmap for accurate scanning")
    from .port_scanner_nmap import scan_ports as scan_ports_advanced
else:
    print("[PortScanner] Nmap not found - using simple socket scanner")
    from .port_scanner_simple import scan_ports as scan_ports_simple

def scan_ports(url: str, port_option: str = "top50", custom_ports: str = None) -> PortScanResult:
    """Smart port scanner - uses Nmap if available"""
    if NMAP_AVAILABLE:
        return scan_ports_advanced(url, port_option, custom_ports)
    else:
        return scan_ports_simple(url, port_option, custom_ports)
