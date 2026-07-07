from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

router = APIRouter(prefix="/api/email", tags=["email"])

CONFIG_FILE = "email_config.json"

class EmailConfig(BaseModel):
    sender_email: str = ""
    app_password: str = ""
    recipient_emails: str = ""

class TestEmailRequest(BaseModel):
    sender_email: str
    app_password: str
    recipient_emails: str

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except:
        return {"sender_email": "", "app_password": "", "recipient_emails": ""}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

@router.get("/config")
async def get_email_config():
    return load_config()

@router.post("/config")
async def save_email_config(config: EmailConfig):
    save_config(config.dict())
    return {"status": "success", "message": "Configuration saved"}

@router.post("/test")
async def test_email(request: TestEmailRequest):
    try:
        msg = MIMEMultipart()
        msg['From'] = request.sender_email
        recipients = [r.strip() for r in request.recipient_emails.split(",") if r.strip()]
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = "Recon Tool - Test Email"
        msg.attach(MIMEText("✅ This is a test email from Recon Tool. Your email configuration is working!", "plain"))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(request.sender_email, request.app_password)
        server.send_message(msg)
        server.quit()
        
        return {"status": "success", "message": "Test email sent successfully!"}
    except Exception as e:
        return {"status": "error", "message": str(e)}