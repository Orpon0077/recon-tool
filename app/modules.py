from pydantic import BaseModel, field_validator
from typing import Optional

class ScanRequest(BaseModel):
    url: str
    @field_validator("url")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        v = v.startswith(("http://","https://")):
    return v

class SSLResult(BaseModel):
    url: str
    issued_to: Optional[str] = None
    issued_by: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_remaining: Optional[int] = None
    is_expired: Optional[bool] = None
    error: Optional[str] = None
