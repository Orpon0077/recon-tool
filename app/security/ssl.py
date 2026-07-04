import ssl
import socket
import datetime
from typing import Dict, Optional
from urllib.parse import urlparse

def analyze_ssl(url: str) -> Dict:
    """
    SSL certificate analysis – returns format expected by frontend renderSSL()
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return {"error": "Invalid URL"}

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')

                if not_after:
                    expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - datetime.datetime.now()).days
                else:
                    days_remaining = None

                is_expired = days_remaining < 0 if days_remaining is not None else False

                return {
                    "issued_to": subject.get('commonName', 'N/A'),
                    "issued_by": issuer.get('organizationName', issuer.get('commonName', 'N/A')),
                    "valid_from": not_before or 'N/A',
                    "valid_until": not_after or 'N/A',
                    "days_remaining": days_remaining if days_remaining is not None else 0,
                    "is_expired": is_expired,
                }

    except ssl.SSLError as e:
        return {"error": f"SSL Error: {str(e)}"}
    except socket.timeout:
        return {"error": "Connection timed out"}
    except Exception as e:
        return {"error": str(e)}