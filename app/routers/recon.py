import asyncio
from fastapi import APIRouter, HTTPException
from app.models import (
    ScanRequest, SSLResult, SecurityHeadersResult,
    PortScanResult, ScreenshotResult, FirewallResult,
    TechDetectionResult, CrawlResult, JSScanResult, SubdomainResult
)

from app.security.ssl import analyze_ssl
from app.security.headers import analyze_security_headers
from app.port_scanner.scanner import scan_ports
from app.screenshot.capture import capture_screenshot
from app.firewall.detection import detect_firewall
from app.tech.detection import detect_technologies
from app.crawl.crawler import crawl_website
from app.js_scanner.scanner import scan_javascript
from app.subdomain.discovery import discover_subdomains
from app.database.db import save_scan, get_all_scans, get_scan_by_id

router = APIRouter(prefix="/api", tags=["recon"])

@router.post("/scan")
async def api_full_scan(payload: ScanRequest) -> dict:
    try:
        url = payload.url
        
        async def run_sync_with_timeout(func, *args, timeout=30):
            try:
                return await asyncio.wait_for(asyncio.to_thread(func, *args), timeout=timeout)
            except asyncio.TimeoutError:
                return {"error": f"Timeout after {timeout}s"}
        
        async def run_async_with_timeout(func, *args, timeout=30):
            try:
                return await asyncio.wait_for(func(*args), timeout=timeout)
            except asyncio.TimeoutError:
                return {"error": f"Timeout after {timeout}s"}
        
        # ── Modules with increased timeouts ──
        ssl_task = run_sync_with_timeout(analyze_ssl, url, timeout=15)          # 8→15s
        security_task = run_sync_with_timeout(analyze_security_headers, url, timeout=15)  # 8→15s
        firewall_task = run_sync_with_timeout(detect_firewall, url, timeout=25)  # 8→25s
        tech_task = run_sync_with_timeout(detect_technologies, url, timeout=20)  # 12→20s
        crawl_task = run_sync_with_timeout(crawl_website, url, timeout=45)       # 30→45s
        subdomain_task = run_sync_with_timeout(discover_subdomains, url, timeout=60)  # 50→60s
        js_task = run_sync_with_timeout(scan_javascript, url, timeout=25)        # 18→25s
        ports_task = run_sync_with_timeout(scan_ports, url, payload.port_option, payload.custom_ports, timeout=35)  # 30→35s
        screenshot_task = asyncio.create_task(run_async_with_timeout(capture_screenshot, url, timeout=60))  # 45→60s
        
        ssl_result, security_result, firewall_result, tech_result, crawl_result, subdomain_result, js_result, ports_result = await asyncio.gather(
            ssl_task, security_task, firewall_task, tech_task, crawl_task, subdomain_task, js_task, ports_task,
            return_exceptions=True
        )
        
        screenshot_result = await screenshot_task
        
        # ── Handle exceptions ──
        def handle_result(result):
            if isinstance(result, Exception):
                return {"error": str(result)}
            if hasattr(result, 'dict'):
                return result.dict()
            return result
        
        result = {
            "url": url,
            "ssl": handle_result(ssl_result),
            "security_headers": handle_result(security_result),
            "ports": handle_result(ports_result),
            "screenshot": handle_result(screenshot_result),
            "firewall": handle_result(firewall_result),
            "tech": handle_result(tech_result),
            "crawl": handle_result(crawl_result),
            "subdomains": handle_result(subdomain_result),
            "js_scanner": handle_result(js_result)
        }
        
        scan_id = await save_scan(url, result)
        result["scan_id"] = scan_id
        
        return result
        
    except Exception as e:
        print(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_history():
    return await get_all_scans()


@router.get("/history/{scan_id}")
async def get_history_item(scan_id: str):
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
    result = await asyncio.to_thread(scan_javascript, payload.url)
    if result.get("error"):
        return JSScanResult(error=result["error"])
    return JSScanResult(**result)


@router.post("/subdomains", response_model=SubdomainResult)
async def api_subdomains(payload: ScanRequest) -> SubdomainResult:
    result = await asyncio.to_thread(discover_subdomains, payload.url)
    return SubdomainResult(**result)


@router.post("/export-pdf")
async def export_pdf(payload: dict):
    try:
        from app.report.pdf_generator import generate_pdf_report
        filepath = await asyncio.to_thread(generate_pdf_report, payload, payload.get('url', 'unknown'))
        return {"success": True, "filepath": filepath, "download_url": f"/{filepath}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
