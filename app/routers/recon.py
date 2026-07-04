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
        ssl_task = run_sync_with_timeout(analyze_ssl, url, timeout=15)
        security_task = run_sync_with_timeout(analyze_security_headers, url, timeout=15)
        firewall_task = run_sync_with_timeout(detect_firewall, url, timeout=25)
        tech_task = run_sync_with_timeout(detect_technologies, url, timeout=20)
        crawl_task = run_sync_with_timeout(crawl_website, url, timeout=45)
        subdomain_task = run_sync_with_timeout(discover_subdomains, url, timeout=60)
        js_task = run_sync_with_timeout(scan_javascript, url, timeout=25)
        ports_task = run_sync_with_timeout(scan_ports, url, payload.port_option, payload.custom_ports, timeout=35)
        screenshot_task = asyncio.create_task(run_async_with_timeout(capture_screenshot, url, timeout=60))
        
        ssl_result, security_result, firewall_result, tech_result, crawl_result, subdomain_result, js_result, ports_result = await asyncio.gather(
            ssl_task, security_task, firewall_task, tech_task, crawl_task, subdomain_task, js_task, ports_task,
            return_exceptions=True
        )
        
        screenshot_result = await screenshot_task
        
        def handle_result(result):
            if isinstance(result, Exception):
                return {"error": str(result)}
            if hasattr(result, 'dict'):
                return result.dict()
            if isinstance(result, dict):
                return result
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


# ── Individual endpoints (all return dict for simplicity) ──

@router.post("/ssl")
async def api_ssl(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(analyze_ssl, payload.url)


@router.post("/security-headers")
async def api_security(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(analyze_security_headers, payload.url)


@router.post("/ports")
async def api_ports(payload: ScanRequest) -> dict:
    result = await asyncio.to_thread(scan_ports, payload.url, payload.port_option, payload.custom_ports)
    if hasattr(result, 'dict'):
        return result.dict()
    return result


@router.post("/screenshot")
async def api_screenshot(payload: ScanRequest) -> dict:
    result = await capture_screenshot(payload.url)
    if hasattr(result, 'dict'):
        return result.dict()
    return result


@router.post("/firewall")
async def api_firewall(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(detect_firewall, payload.url)


@router.post("/tech")
async def api_tech(payload: ScanRequest) -> dict:
    result = await asyncio.to_thread(detect_technologies, payload.url)
    if hasattr(result, 'dict'):
        return result.dict()
    return result


@router.post("/crawl")
async def api_crawl(payload: ScanRequest) -> dict:
    result = await asyncio.to_thread(crawl_website, payload.url)
    if hasattr(result, 'dict'):
        return result.dict()
    return result


@router.post("/js-scan")
async def api_js_scan(payload: ScanRequest) -> dict:
    result = await asyncio.to_thread(scan_javascript, payload.url)
    # result is guaranteed to be a dict with at least an "error" key if failed
    return result


@router.post("/subdomains")
async def api_subdomains(payload: ScanRequest) -> dict:
    result = await asyncio.to_thread(discover_subdomains, payload.url)
    if hasattr(result, 'dict'):
        return result.dict()
    return result


@router.post("/export-pdf")
async def export_pdf(payload: dict):
    try:
        from app.report.pdf_generator import generate_pdf_report
        filepath = await asyncio.to_thread(generate_pdf_report, payload, payload.get('url', 'unknown'))
        return {"success": True, "filepath": filepath, "download_url": f"/{filepath}"}
    except Exception as e:
        return {"success": False, "error": str(e)}