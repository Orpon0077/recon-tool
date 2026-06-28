# ── Automation Core ──────────────────────────────────────────
# Handles automated scans, email, and reporting

import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from pathlib import Path
import os
from app.modules import (
    analyze_ssl, analyze_security_headers, scan_ports,
    capture_screenshot, detect_firewall, detect_technologies,
    crawl_website, scan_javascript, discover_subdomains
)
from app.database import save_scan

# ── Email Configuration (from .env) ──
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "")
RECIPIENT_EMAILS = os.getenv("RECIPIENT_EMAILS", "").split(",")

# ── Automated Scan ──
async def run_automated_scan(url: str) -> dict:
    """Run full automated scan"""
    try:
        print(f"[Automation] Scanning: {url}")
        
        # Run all modules
        ssl = await asyncio.to_thread(analyze_ssl, url)
        security = await asyncio.to_thread(analyze_security_headers, url)
        ports = await asyncio.to_thread(scan_ports, url)
        screenshot = await capture_screenshot(url)
        firewall = await asyncio.to_thread(detect_firewall, url)
        tech = await asyncio.to_thread(detect_technologies, url)
        crawl = await asyncio.to_thread(crawl_website, url)
        js = await asyncio.to_thread(scan_javascript, url)
        subdomains = await asyncio.to_thread(discover_subdomains, url)
        
        result = {
            "url": url,
            "ssl": ssl.dict() if hasattr(ssl, 'dict') else ssl,
            "security_headers": security.dict() if hasattr(security, 'dict') else security,
            "ports": ports.dict() if hasattr(ports, 'dict') else ports,
            "screenshot": screenshot.dict() if hasattr(screenshot, 'dict') else screenshot,
            "firewall": firewall.dict() if hasattr(firewall, 'dict') else firewall,
            "tech": tech.dict() if hasattr(tech, 'dict') else tech,
            "crawl": crawl.dict() if hasattr(crawl, 'dict') else crawl,
            "js_scanner": js if isinstance(js, dict) else js.dict() if hasattr(js, 'dict') else js,
            "subdomains": subdomains if isinstance(subdomains, dict) else subdomains.dict() if hasattr(subdomains, 'dict') else subdomains
        }
        
        # Save to database
        scan_id = await save_scan(url, result)
        
        # Generate PDF
        try:
            from app.modules.pdf_generator import generate_pdf_report
            pdf_path = await asyncio.to_thread(generate_pdf_report, result, url)
            result["pdf_path"] = pdf_path
            print(f"[Automation] ✅ PDF generated: {pdf_path}")
        except Exception as e:
            print(f"[Automation] PDF generation failed: {e}")
        
        print(f"[Automation] ✅ Scan complete: {url} (ID: {scan_id})")
        
        return {
            "success": True,
            "scan_id": scan_id,
            "result": result
        }
        
    except Exception as e:
        print(f"[Automation] ❌ Scan failed for {url}: {e}")
        return {"success": False, "error": str(e)}

# ── Email Notification ──
async def send_email_report(url: str, result: dict):
    """Send email report with PDF attachment"""
    if not EMAIL_ENABLED or not SENDER_EMAIL:
        print("[Automation] Email disabled or not configured")
        return
    
    try:
        subject = f"[Recon] Scan Complete: {url}"
        
        body = f"""
Scan Complete: {url}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Summary:
- SSL: {result.get('ssl', {}).get('issued_to', 'N/A')}
- Security Score: {result.get('security_headers', {}).get('score', 0)}/100
- Open Ports: {result.get('ports', {}).get('total_open', 0)}
- Subdomains: {result.get('subdomains', {}).get('total_found', 0)}
- Technologies: {result.get('tech', {}).get('total_found', 0)}
- Endpoints: {result.get('crawl', {}).get('total_found', 0)}

View Report: http://localhost:8000/?scan_id={result.get('scan_id', '')}
        """
        
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECIPIENT_EMAILS)
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach PDF if available
        pdf_path = result.get('pdf_path')
        if pdf_path and os.path.exists(pdf_path):
            try:
                with open(pdf_path, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    filename = Path(pdf_path).name
                    part.add_header('Content-Disposition', f'attachment; filename={filename}')
                    msg.attach(part)
                    print(f"[Automation] ✅ PDF attached: {filename}")
            except Exception as e:
                print(f"[Automation] PDF attach failed: {e}")
        
        # Send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"[Automation] ✅ Email sent to {', '.join(RECIPIENT_EMAILS)}")
        
    except Exception as e:
        print(f"[Automation] ❌ Email failed: {e}")

# ── Send Complete Report ──
async def send_scan_report(url: str, result: dict):
    """Send all notifications"""
    tasks = []
    
    # Email
    if EMAIL_ENABLED:
        tasks.append(send_email_report(url, result))
    
    if tasks:
        await asyncio.gather(*tasks)
