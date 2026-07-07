# ── Automation Core ──────────────────────────────────────────
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from pathlib import Path
import os
import json

from app.security.ssl import analyze_ssl
from app.security.headers import analyze_security_headers
from app.port_scanner.scanner import scan_ports
from app.screenshot.capture import capture_screenshot
from app.firewall.detection import detect_firewall
from app.tech.detection import detect_technologies
from app.crawl.crawler import crawl_website
from app.js_scanner.scanner import scan_javascript
from app.subdomain.discovery import discover_subdomains
from app.database.db import save_scan

# ── Email Configuration ──
EMAIL_CONFIG_FILE = "email_config.json"

def load_email_config():
    try:
        with open(EMAIL_CONFIG_FILE, "r") as f:
            return json.load(f)
    except:
        return {"sender_email": "", "app_password": "", "recipient_emails": ""}

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

def safe_dict(obj):
    """Safely convert object to dict"""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, 'dict'):
        return obj.dict()
    return obj

async def run_automated_scan(url: str) -> dict:
    """Full automated scan with all modules"""
    try:
        url = normalize_url(url)
        print(f"[Automation] 🔍 Scanning: {url}")
        start_time = datetime.now()
        
        # ── Run all modules in parallel ──
        tasks = [
            asyncio.to_thread(analyze_ssl, url),
            asyncio.to_thread(analyze_security_headers, url),
            asyncio.to_thread(scan_ports, url),
            capture_screenshot(url),
            asyncio.to_thread(detect_firewall, url),
            asyncio.to_thread(detect_technologies, url),
            asyncio.to_thread(crawl_website, url),
            asyncio.to_thread(scan_javascript, url),
            asyncio.to_thread(discover_subdomains, url),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # ── Handle results ──
        ssl = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
        security = results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])}
        ports = results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])}
        screenshot = results[3] if not isinstance(results[3], Exception) else {"error": str(results[3])}
        firewall = results[4] if not isinstance(results[4], Exception) else {"error": str(results[4])}
        tech = results[5] if not isinstance(results[5], Exception) else {"error": str(results[5])}
        crawl = results[6] if not isinstance(results[6], Exception) else {"error": str(results[6])}
        js = results[7] if not isinstance(results[7], Exception) else {"error": str(results[7])}
        subdomains = results[8] if not isinstance(results[8], Exception) else {"error": str(results[8])}
        
        # ── Build result ──
        result = {
            "url": url,
            "timestamp": start_time.isoformat(),
            "ssl": safe_dict(ssl),
            "security_headers": safe_dict(security),
            "ports": safe_dict(ports),
            "screenshot": safe_dict(screenshot),
            "firewall": safe_dict(firewall),
            "tech": safe_dict(tech),
            "crawl": safe_dict(crawl),
            "js_scanner": safe_dict(js),
            "subdomains": safe_dict(subdomains),
        }
        
        # ── Generate PDF ──
        try:
            from app.report.pdf_generator import generate_pdf_report
            pdf_path = await asyncio.to_thread(generate_pdf_report, result, url)
            result["pdf_path"] = pdf_path
        except Exception as e:
            print(f"[Automation] PDF generation failed: {e}")
            result["pdf_path"] = None
        
        # ── Save to database ──
        scan_id = await save_scan(url, result)
        result["scan_id"] = scan_id
        
        duration = (datetime.now() - start_time).total_seconds()
        print(f"[Automation] ✅ Scan complete: {url} (ID: {scan_id}, {duration:.1f}s)")
        
        return {"success": True, "scan_id": scan_id, "result": result}
        
    except Exception as e:
        print(f"[Automation] ❌ Scan failed: {e}")
        return {"success": False, "error": str(e), "scan_id": None}


async def send_email_report(url: str, result: dict):
    """Send email notification with scan results"""
    config = load_email_config()
    sender = config.get("sender_email", "").strip()
    password = config.get("app_password", "").strip()
    recipients_raw = config.get("recipient_emails", "").strip()
    
    if not sender or not password or not recipients_raw:
        print("[Automation] 📧 Email config missing, skipping")
        return
    
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        print("[Automation] 📧 No recipients, skipping")
        return
    
    try:
        scan_id = result.get("scan_id", "N/A")
        timestamp = result.get("timestamp", datetime.now().isoformat())
        
        # ── Build summary ──
        ssl_data = result.get("ssl", {})
        security_data = result.get("security_headers", {})
        ports_data = result.get("ports", {})
        subdomains_data = result.get("subdomains", {})
        tech_data = result.get("tech", {})
        
        tech_count = 0
        if tech_data and isinstance(tech_data, dict):
            techs = tech_data.get("technologies", {})
            tech_count = sum(len(v) for v in techs.values()) if isinstance(techs, dict) else 0
        
        subject = f"[RECON TOOL] Scan Complete: {url}"
        
        body = f"""
╔══════════════════════════════════════╗
║     SCAN COMPLETE REPORT            ║
╚══════════════════════════════════════╝

📍 Target URL: {url}
🆔 Scan ID: {scan_id}
🕐 Time: {timestamp}

📊 SUMMARY:
─────────────────────────────────────
🔐 SSL: {ssl_data.get('issued_to', 'N/A') if ssl_data else 'N/A'}
🛡️ Security Score: {security_data.get('score', 0) if security_data else 0}/100
🔌 Open Ports: {ports_data.get('total_open', 0) if ports_data else 0}
🌐 Subdomains: {subdomains_data.get('total_found', 0) if subdomains_data else 0}
📦 Technologies: {tech_count} found
📄 Endpoints: {result.get('crawl', {}).get('total_found', 0) if result.get('crawl') else 0}

📎 PDF Report: {'✅ Generated' if result.get('pdf_path') else '❌ Failed'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
View full report in dashboard:
http://localhost:8000/?scan_id={scan_id}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generated by Recon Tool v1.0
"""
        
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # ── Attach PDF if available ──
        pdf_path = result.get('pdf_path')
        if pdf_path and os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={Path(pdf_path).name}')
                msg.attach(part)
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
        
        print(f"[Automation] 📧 Email sent to {len(recipients)} recipient(s)")
        return True
        
    except Exception as e:
        print(f"[Automation] 📧 Email failed: {e}")
        return False


async def send_scan_report(url: str, result: dict):
    """Alias for send_email_report"""
    await send_email_report(url, result)