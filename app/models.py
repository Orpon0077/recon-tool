from pydantic import BaseModel, field_validator
from typing import Optional


# ── Request Model ──────────────────────────────────────────
# User যে URL পাঠাবে সেটার ছাঁচ
class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v


# ── SSL/TLS Analysis ───────────────────────────────────────
# SSL certificate এর তথ্য রাখে
class SSLResult(BaseModel):
    url: str
    issued_to: Optional[str] = None       # certificate কাকে দেওয়া হয়েছে
    issued_by: Optional[str] = None       # কোন authority দিয়েছে
    valid_from: Optional[str] = None      # কবে থেকে valid
    valid_until: Optional[str] = None     # কবে পর্যন্ত valid
    days_remaining: Optional[int] = None  # কতদিন বাকি
    is_expired: Optional[bool] = None     # মেয়াদ শেষ কিনা
    error: Optional[str] = None           # error হলে এখানে আসবে


# ── Security Headers Analysis ─────────────────────────────────
#Security header এর তথ্য রাখে
class SecurityHeadersResult(BaseModel):
    url: str
    present: dict[str, str] = {}              # পাওয়া security headers
    missing: list[str] = []          # অনুপস্থিত security headers
    score: int = 0                             # security headers এর স্কোর (0-100)
    error: Optional[str] = None           # error হলে এখানে আসবে