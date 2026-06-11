# ── Recon Router ──────────────────────────────────────────
import asyncio
from fastapi import APIRouter, HTTPException
from app.models import (
    ScanRequest, FullReport, SSLResult, SecurityHeadersResult,
    PortScanResult, ScreenshotResult, FirewallResult,
    TechDetectionResult, CrawlResult, JSScanResult
)
from app.modules import (
    analyze_ssl,
    analyze_security_headers,
    scan_ports,
    capture_screenshot,
    detect_firewall,
    detect_technologies,
    crawl_website,
    scan_javascript
)
from app.database import save_scan, get_all_scans, get_scan_by_id

router = APIRouter(prefix="/api", tags=["recon"])

@router.post("/scan")
async def api_full_scan(payload: ScanRequest) -> dict:
    """Full scan with all modules"""
    try:
        url = payload.url
        
        # Run all modules concurrently
        ssl_task = asyncio.to_thread(analyze_ssl, url)
        security_task = asyncio.to_thread(analyze_security_headers, url)
        ports_task = asyncio.to_thread(scan_ports, url, payload.port_option, payload.custom_ports)
        screenshot_task = capture_screenshot(url)
        firewall_task = asyncio.to_thread(detect_firewall, url)
        tech_task = asyncio.to_thread(detect_technologies, url)
        crawl_task = asyncio.to_thread(crawl_website, url)
        
        # Wait for all tasks
        ssl_result, security_result, ports_result, screenshot_result, firewall_result, tech_result, crawl_result = await asyncio.gather(
            ssl_task, security_task, ports_task, screenshot_task, firewall_task, tech_task, crawl_task
        )
        
        # Prepare result
        result = {
            "url": url,
            "ssl": ssl_result.dict() if hasattr(ssl_result, 'dict') else ssl_result,
            "security_headers": security_result.dict() if hasattr(security_result, 'dict') else security_result,
            "ports": ports_result.dict() if hasattr(ports_result, 'dict') else ports_result,
            "screenshot": screenshot_result.dict() if hasattr(screenshot_result, 'dict') else screenshot_result,
            "firewall": firewall_result.dict() if hasattr(firewall_result, 'dict') else firewall_result,
            "tech": tech_result.dict() if hasattr(tech_result, 'dict') else tech_result,
            "crawl": crawl_result.dict() if hasattr(crawl_result, 'dict') else crawl_result
        }
        
        # Save to database
        scan_id = await save_scan(url, result)
        result["scan_id"] = scan_id
        
        return result
        
    except Exception as e:
        print(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_history():
    """Get all scan history"""
    return await get_all_scans()


@router.get("/history/{scan_id}")
async def get_history_item(scan_id: str):
    """Get a single scan by ID"""
    return await get_scan_by_id(scan_id)


@router.post("/ssl")
async def api_ssl(payload: ScanRequest) -> SSLResult:
    return await asyncio.to_thread(analyze_ssl, payload.url)


@router.post("/security-headers")
async def api_security(payload: ScanRequest) -> SecurityHeadersResult:
    return await asyncio.to_thread(analyze_security_headers, payload.url)


@router.post("/ports")
async def api_ports(payload: ScanRequest) -> PortScanResult:
    return await asyncio.to_thread(scan_ports, payload.url, payload.port_option, payload.custom_ports)


@router.post("/screenshot")
async def api_screenshot(payload: ScanRequest) -> ScreenshotResult:
    return await capture_screenshot(payload.url)


@router.post("/firewall")
async def api_firewall(payload: ScanRequest) -> FirewallResult:
    return await asyncio.to_thread(detect_firewall, payload.url)


@router.post("/tech")
async def api_tech(payload: ScanRequest) -> TechDetectionResult:
    return await asyncio.to_thread(detect_technologies, payload.url)


@router.post("/crawl")
async def api_crawl(payload: ScanRequest) -> CrawlResult:
    return await asyncio.to_thread(crawl_website, payload.url)


@router.post("/js-scan", response_model=JSScanResult)
async def api_js_scan(payload: ScanRequest) -> JSScanResult:
    """Scan JavaScript files for API endpoints, emails, tokens etc."""
    result = await asyncio.to_thread(scan_javascript, payload.url)
    if result.get("error"):
        return JSScanResult(error=result["error"])
    return JSScanResult(**result)