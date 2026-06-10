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
    FirewallResult,
    TechDetectionResult,
    CrawlResult,
)
from app.modules import (
    analyze_ssl,
    analyze_security_headers,
    scan_ports,
    capture_screenshot,
    detect_firewall,
    detect_technologies,
    crawl_website,
)
from app.database import save_scan

router = APIRouter(prefix="/api", tags=["recon"])


# ── SSL/TLS Analysis ───────────────────────────────────────
@router.post("/ssl", response_model=SSLResult)
async def api_ssl(payload: ScanRequest):
    return await asyncio.to_thread(analyze_ssl, payload.url)


# ── Security Headers Analysis ──────────────────────────────
@router.post("/security-headers", response_model=SecurityHeadersResult)
async def api_security_headers(payload: ScanRequest):
    return await asyncio.to_thread(analyze_security_headers, payload.url)


# ── Port Scanning ──────────────────────────────────────────
@router.post("/ports", response_model=PortScanResult)
async def api_ports(payload: ScanRequest):
    return await asyncio.to_thread(scan_ports, payload.url)


# ── Screenshot ─────────────────────────────────────────────
@router.post("/screenshot", response_model=ScreenshotResult)
async def api_screenshot(payload: ScanRequest):
    return await capture_screenshot(payload.url)


# ── Firewall Detection ─────────────────────────────────────
@router.post("/firewall", response_model=FirewallResult)
async def api_firewall(payload: ScanRequest):
    return await asyncio.to_thread(detect_firewall, payload.url)


# ── Tech Detection ─────────────────────────────────────────
@router.post("/tech", response_model=TechDetectionResult)
async def api_tech(payload: ScanRequest):
    return await asyncio.to_thread(detect_technologies, payload.url)


# ── Crawling ───────────────────────────────────────────────
@router.post("/crawl", response_model=CrawlResult)
async def api_crawl(payload: ScanRequest):
    return await asyncio.to_thread(crawl_website, payload.url)


# ── Full Scan — সব modules একসাথে + MongoDB তে save ────────
@router.post("/scan")
async def api_full_scan(payload: ScanRequest):
    # সব modules একসাথে চালাও
    (
        ssl_result,
        sec_result,
        ports_result,
        screenshot_result,
        firewall_result,
        tech_result,
        crawl_result,
    ) = await asyncio.gather(
        asyncio.to_thread(analyze_ssl, payload.url),
        asyncio.to_thread(analyze_security_headers, payload.url),
        asyncio.to_thread(scan_ports, payload.url),
        capture_screenshot(payload.url),
        asyncio.to_thread(detect_firewall, payload.url),
        asyncio.to_thread(detect_technologies, payload.url),
        asyncio.to_thread(crawl_website, payload.url),
    )

    # সব result একটা dictionary তে রাখো
    results = {
        "ssl":              ssl_result.model_dump(),
        "security_headers": sec_result.model_dump(),
        "ports":            ports_result.model_dump(),
        "screenshot":       screenshot_result.model_dump(),
        "firewall":         firewall_result.model_dump(),
        "tech":             tech_result.model_dump(),
        "crawl":            crawl_result.model_dump(),
    }

    # MongoDB তে save করো
    scan_id = await save_scan(payload.url, results)
    return {"scan_id": scan_id, **results}