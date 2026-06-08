# ── Recon Router ───────────────────────────────────────────
# সব API endpoints এখানে define করা আছে

import asyncio
from fastapi import APIRouter
from app.models import (
    ScanRequest,
    SSLResult,
    SecurityHeadersResult,
    PortScanResult,
    ScreenshotResult,
)
from app.modules import (
    analyze_ssl,
    analyze_security_headers,
    scan_ports,
    capture_screenshot,
)

router = APIRouter(prefix="/api", tags=["recon"])


# ── SSL/TLS Analysis ───────────────────────────────────────
# POST /api/ssl
@router.post("/ssl", response_model=SSLResult)
async def api_ssl(payload: ScanRequest):
    return await asyncio.to_thread(analyze_ssl, payload.url)


# ── Security Headers Analysis ──────────────────────────────
# POST /api/security-headers
@router.post("/security-headers", response_model=SecurityHeadersResult)
async def api_security_headers(payload: ScanRequest):
    return await asyncio.to_thread(analyze_security_headers, payload.url)


# ── Port Scanning ──────────────────────────────────────────
# POST /api/ports
@router.post("/ports", response_model=PortScanResult)
async def api_ports(payload: ScanRequest):
    return await asyncio.to_thread(scan_ports, payload.url)


# ── Screenshot ─────────────────────────────────────────────
# POST /api/screenshot
@router.post("/screenshot", response_model=ScreenshotResult)
async def api_screenshot(payload: ScanRequest):
    return await capture_screenshot(payload.url)