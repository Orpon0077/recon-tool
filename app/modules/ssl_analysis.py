import ssl
import socket
from datetime import datetime
from app.models import SSLResult


def analyze_ssl(url: str) -> SSLResult:
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
        conn.settimeout(10)
        conn.connect((hostname, 443))

        cert = conn.getpeercert()
        conn.close()

        issued_to = dict(cert["subject"][0]).get("commonName", "Unknown")
        issued_by = dict(cert["issuer"][0]).get("organizationName", "Unknown")
        valid_from = cert["notBefore"]
        valid_until = cert["notAfter"]

        expiry_date = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days
        is_expired = days_remaining < 0

        return SSLResult(
            url=url,
            issued_to=issued_to,
            issued_by=issued_by,
            valid_from=valid_from,
            valid_until=valid_until,
            days_remaining=days_remaining,
            is_expired=is_expired,
        )

    except ssl.SSLError as e:
        return SSLResult(url=url, error=f"SSL Error: {str(e)}")
    except socket.timeout:
        return SSLResult(url=url, error="Connection timed out")
    except Exception as e:
        return SSLResult(url=url, error=str(e))
