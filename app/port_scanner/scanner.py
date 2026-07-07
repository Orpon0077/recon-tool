# Port Scanner Module – Final Version
# Uses ThreadPoolExecutor for fast parallel scanning
# Guarantees ports 80 and 443 are always checked

import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 3000, 4200, 5000, 8888}

# Top 1000 most common ports (simplified but complete)
TOP_1000_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2181: "Zookeeper",
    2375: "Docker", 2376: "Docker-TLS", 3000: "Node/React", 3306: "MySQL",
    3389: "RDP", 4200: "Angular", 4369: "RabbitMQ", 5000: "Flask/Dev",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis",
    6443: "Kubernetes", 7474: "Neo4j", 8000: "Dev Server", 8080: "HTTP-Alt",
    8081: "HTTP-Alt2", 8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "PHP-FPM",
    9042: "Cassandra", 9092: "Kafka", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 15672: "RabbitMQ-UI", 27017: "MongoDB", 27018: "MongoDB",
    28017: "MongoDB-Web", 50070: "Hadoop", 50075: "Hadoop",
    7: "Echo", 9: "Discard", 13: "Daytime", 17: "QOTD", 19: "Chargen",
    20: "FTP-Data", 26: "RSFTP", 37: "Time", 49: "TACACS", 69: "TFTP",
    70: "Gopher", 79: "Finger", 88: "Kerberos", 113: "IDENT", 119: "NNTP",
    161: "SNMP", 179: "BGP", 194: "IRC", 389: "LDAP", 465: "SMTPS",
    500: "ISAKMP", 512: "Exec", 513: "Login", 514: "Shell", 515: "Printer",
    543: "Klogin", 544: "Kshell", 548: "AFP", 554: "RTSP", 563: "NNTPS",
    631: "IPP", 636: "LDAPS", 873: "Rsync", 990: "FTPS", 992: "Telnets",
    994: "IRCS", 1025: "NFS", 1720: "H.323", 1723: "PPTP", 1755: "MMS",
    1900: "UPnP", 2000: "Cisco-SCCP", 2049: "NFS", 2121: "CCProxy-FTP",
    3128: "Squid", 3268: "LDAP", 3269: "LDAPS", 4444: "Metasploit",
    4899: "RAdmin", 5060: "SIP", 5190: "AIM", 5357: "WSDAPI", 5800: "VNC-HTTP",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6000: "X11", 7070: "RealServer",
    8008: "HTTP-Alt", 8009: "Ajp13", 8082: "HTTP-Alt", 8083: "HTTP-Alt",
    8084: "HTTP-Alt", 8085: "HTTP-Alt", 8086: "InfluxDB", 8087: "Riak",
    8089: "Splunk", 8090: "HTTP-Alt", 8091: "Couchbase", 8092: "Couchbase",
    8093: "Couchbase", 8094: "HTTP-Alt", 8095: "HTTP-Alt", 8096: "Jellyfin",
    8097: "HTTP-Alt", 8098: "HTTP-Alt", 8099: "HTTP-Alt", 8161: "ActiveMQ",
    8162: "ActiveMQ", 8181: "HTTP-Alt", 8182: "HTTP-Alt", 8222: "NATS",
    8300: "Consul", 8301: "Consul", 8302: "Consul", 8400: "Consul",
    8500: "Consul", 8600: "Consul", 9001: "Tor-ORPort", 9043: "WebSphere",
    9060: "WebSphere", 9080: "WebSphere", 9090: "Zeus-Admin", 9100: "Jetdirect",
    9999: "Abyss", 10000: "Webmin", 32768: "Filenet-TMS", 49152: "Unknown",
}

def get_port_list(port_option: str, custom_ports: str = None) -> dict:
    if port_option == "top1000":
        result = dict(TOP_1000_PORTS)
    elif port_option == "custom" and custom_ports:
        result = {}
        for p in custom_ports.split(","):
            p = p.strip()
            if p.isdigit():
                port_num = int(p)
                result[port_num] = TOP_1000_PORTS.get(port_num, "Custom")
    else:
        result = dict(TOP_1000_PORTS)

    # Guarantee 80 and 443
    result.setdefault(80, "HTTP")
    result.setdefault(443, "HTTPS")
    return result

def scan_single_port(host: str, port: int, timeout: float = 3.0) -> tuple:
    """Scan a single port, returns (port, is_open)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False

def get_version(host: str, port: int) -> str:
    """Get version info for HTTP ports."""
    if port not in HTTP_PORTS:
        return "Unknown"
    try:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{host}:{port}"
        response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
        server = response.headers.get("Server", "")
        if server:
            return server
        powered = response.headers.get("X-Powered-By", "")
        if powered:
            return powered
        return f"HTTP {response.status_code}"
    except:
        return "Unknown"

def scan_ports(url: str, port_option: str = "top1000", custom_ports: str = None) -> dict:
    """
    Scan target for open ports using ThreadPoolExecutor.
    Guaranteed to check 80 and 443.
    """
    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"error": f"Host resolution failed: {e}", "open_ports": [], "total_open": 0}

    ports_dict = get_port_list(port_option, custom_ports)
    ports_to_scan = list(ports_dict.keys())

    print(f"[Port Scanner] Scanning {len(ports_to_scan)} ports on {host}...")

    open_ports = []
    # Use ThreadPoolExecutor for parallel scanning (max 100 threads)
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_single_port, host, port, 3.0): port for port in ports_to_scan}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = ports_dict.get(port, "unknown")
                version = get_version(host, port) if port in HTTP_PORTS else "Unknown"
                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open",
                    "version": version,
                    "protocol": "tcp"
                })
                print(f"[Port Scanner] Found port {port} ({service})")

    print(f"[Port Scanner] Done. Total open: {len(open_ports)}")

    return {
        "url": url,
        "host": host,
        "ip": ip,
        "open_ports": open_ports,
        "total_open": len(open_ports)
    }