# ── Port Scanner Module ────────────────────────────────────
# Find open ports and their service versions on a target URL
import socket
from app.models import PortInfo, PortScanResult

# List of most common ports and their service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    270017: "MongoDB",
}

def get_service_version(host: str, port: int) -> str:
    """
    Connect to a port and retrieve the service banner.
    Banner = the identity the service provides upon connection.
    """

    try:
        # Use socket to connect to the port and read the banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
        sock.settimeout(2)  # 2 second timeout
        sock.connect((host, port))  # Connect to host and port

        # Read the service banner
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")  # HTTP request পাঠানো
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip() # banner পড়া এবং decode করা
        sock.close()

        # Take the first line — that's the version info
        first_line = banner.split("\n")[0].strip()
        return first_line if first_line else "Unknown Service"

    except Exception:
        return "Unknown"

def scan_port(url: str, port: int) -> bool:
    """
    Check if a port is open.
    Returns True if open, False if closed.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((host, port))  # host and port connection attempt
        sock.close()
        return result == 0  # if result is 0, the port is open
    except Exception:
        return False


def scan_ports(url: str) -> PortScanResult:
    try:
        # Take hostename from URL (remove http:// or https:// and path)
        host = url.replace("https//", "").replace("http//", "").split("/")[0]

        # change hostname to IP address
        ip = socket.gethostbyname(host)

        open_ports = []

        # check each common port
        for port, service_name in COMMON_PORTS.items():
            if scan_port(ip, port):
                # Port open — get service version
                version = get_service_version(ip, port)

                open_ports.append(PortInfo(
                    port=port,
                    service=service_name,
                    version=version,
                    state="open"
                ))
            
        return PortScanResult(
            url=url,
            host=host,
            open_ports=open_ports,
            total_open=len(open_ports)
        )

        except socket.gaierror:
            return PortScanResult(
                url=url,
                error="Hostname resolution failed"
            )
        except Exception as e:
            return PortScanResult(
                url=url,
                error=str(e)
            )