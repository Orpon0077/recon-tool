from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict

# ── Scan Request ───────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str
    port_option: str = "top50"
    custom_ports: Optional[str] = None

    @field_validator("url")
    @classmethod
    def normalize_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v

    @field_validator("custom_ports", mode="before")
    @classmethod
    def handle_custom_ports(cls, v):
        if v is None:
            return None
        if v == "":
            return None
        return str(v)


# ── SSL Result ─────────────────────────────────────────────
class SSLResult(BaseModel):
    url: str
    issued_to: Optional[str] = None
    issued_by: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_remaining: Optional[int] = None
    is_expired: bool = False
    error: Optional[str] = None


# ── Security Headers Result ─────────────────────────────────
class SecurityHeadersResult(BaseModel):
    url: str
    score: int = 0
    present: Dict[str, str] = {}
    missing: List[str] = []
    error: Optional[str] = None


# ── Port Info ──────────────────────────────────────────────
class PortInfo(BaseModel):
    port: int
    service: str
    version: str
    state: str = "open"


# ── Port Scan Result ───────────────────────────────────────
class PortScanResult(BaseModel):
    url: str
    host: str
    open_ports: List[PortInfo] = []
    total_open: int = 0
    vulnerabilities: List[dict] = []
    os_info: dict = {}
    error: Optional[str] = None


# ── Screenshot Result ──────────────────────────────────────
class ScreenshotResult(BaseModel):
    url: str
    screenshot_path: Optional[str] = None
    error: Optional[str] = None


# ── Firewall Result ────────────────────────────────────────
class FirewallResult(BaseModel):
    url: str
    detected: bool = False
    firewall_name: Optional[str] = None
    evidence: str = "No firewall detected"
    error: Optional[str] = None


# ── Tech Detection Result ──────────────────────────────────
class TechDetectionResult(BaseModel):
    url: str
    technologies: Dict[str, List[str]] = {}
    total_found: int = 0
    error: Optional[str] = None


# ── Endpoint Info ──────────────────────────────────────────
class EndpointInfo(BaseModel):
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None


# ── Crawl Result ───────────────────────────────────────────
class CrawlResult(BaseModel):
    url: str
    endpoints: List[EndpointInfo] = []
    total_found: int = 0
    error: Optional[str] = None


# ── Full Report ────────────────────────────────────────────
class FullReport(BaseModel):
    url: str
    ssl: SSLResult
    security_headers: SecurityHeadersResult
    ports: PortScanResult
    screenshot: ScreenshotResult
    firewall: FirewallResult
    tech: TechDetectionResult
    crawl: CrawlResult


# ── JS Scanner Result ──────────────────────────────────────
class JSScanResult(BaseModel):
    total_js_files: int = 0
    js_files: List[dict] = []
    api_endpoints: List[str] = []
    emails: List[str] = []
    tokens: List[str] = []
    internal_paths: List[str] = []
    social_media: List[str] = []
    error: Optional[str] = None


# ── Subdomain Result ───────────────────────────────────────
class SubdomainResult(BaseModel):
    domain: str
    subdomains: List[dict] = []
    total_found: int = 0
    error: Optional[str] = None


# ── Subdomain Result ───────────────────────────────────────
class SubdomainResult(BaseModel):
    domain: str
    subdomains: List[dict] = []
    total_found: int = 0
    error: Optional[str] = None