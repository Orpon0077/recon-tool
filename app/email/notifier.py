# ── Email Configuration Router ─────────────────────────────
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

router = APIRouter(prefix="/api/email", tags=["email"])

CONFIG_FILE = "email_config.txt"

class EmailConfig(BaseModel):
    sender_email: str
    sender_password: str
    recipients: List[str]

class EmailResponse(BaseModel):
    success: bool
    error: Optional[str] = None

def save_config(sender_email: str, sender_password: str, recipients: List[str]):
    """Save email config to file"""
    with open(CONFIG_FILE, 'w') as f:
        f.write(f"{sender_email}\n")
        f.write(f"{sender_password}\n")
        f.write(','.join(recipients))

def load_config() -> dict:
    """Load email config from file"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                lines = f.read().strip().split('\n')
                if len(lines) >= 3:
                    return {
                        "sender_email": lines[0].strip(),
                        "sender_password": lines[1].strip(),
                        "recipients": [e.strip() for e in lines[2].split(',') if e.strip()]
                    }
    except:
        pass
    return {"sender_email": "", "sender_password": "", "recipients": []}

@router.get("/config")
async def get_email_config():
    config = load_config()
    return {
        "sender_email": config.get("sender_email", ""),
        "sender_password": config.get("sender_password", ""),
        "recipients": config.get("recipients", [])
    }

@router.post("/config")
async def update_email_config(config: EmailConfig):
    try:
        recipients = [e.strip() for e in config.recipients if e.strip()]
        if not recipients:
            return EmailResponse(success=False, error="No valid recipient emails")
        if not config.sender_email or '@' not in config.sender_email:
            return EmailResponse(success=False, error="Invalid sender email")
        if not config.sender_password or len(config.sender_password) < 8:
            return EmailResponse(success=False, error="Invalid app password")
        
        save_config(config.sender_email, config.sender_password, recipients)
        return EmailResponse(success=True)
    except Exception as e:
        return EmailResponse(success=False, error=str(e))

@router.post("/test")
async def send_test_email():
    config = load_config()
    
    sender_email = config.get("sender_email", "")
    sender_password = config.get("sender_password", "")
    recipients = config.get("recipients", [])
    
    if not sender_email or not sender_password:
        return EmailResponse(success=False, error="SMTP not configured. Please save email settings first.")
    
    if not recipients:
        return EmailResponse(success=False, error="No recipients configured. Please add recipient emails.")
    
    try:
        subject = "[Recon] Test Email"
        body = f"""
Test Email from Recon Tool

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Recipients: {', '.join(recipients)}

✅ Email configuration is working!
"""
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = ', '.join(recipients)
        
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        
        return EmailResponse(success=True)
    except Exception as e:
        return EmailResponse(success=False, error=str(e))
