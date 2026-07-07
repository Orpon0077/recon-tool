import asyncio
from fastapi import APIRouter, HTTPException
from app.models import ScanRequest
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

def safe_result(result):
    if isinstance(result, Exception):
        return {"error": str(result)}
    if hasattr(result, 'dict'):
        return result.dict()
    if isinstance(result, dict):
        return result
    if result is None:
        return {"error": "No data returned"}
    return result

async def run_sync_with_timeout(func, *args, timeout=30):
    try:
        return await asyncio.wait_for(asyncio.to_thread(func, *args), timeout=timeout)
    except asyncio.TimeoutError:
        return {"error": f"Timeout after {timeout}s"}

@router.post("/scan")
async def api_full_scan(payload: ScanRequest):
    try:
        url = payload.url

        # ---- Sync modules (run via to_thread) ----
        ssl_task = run_sync_with_timeout(analyze_ssl, url, timeout=15)
        security_task = run_sync_with_timeout(analyze_security_headers, url, timeout=15)
        ports_task = run_sync_with_timeout(scan_ports, url, payload.port_option, payload.custom_ports, timeout=90)
        firewall_task = run_sync_with_timeout(detect_firewall, url, timeout=25)
        tech_task = run_sync_with_timeout(detect_technologies, url, timeout=20)
        js_task = run_sync_with_timeout(scan_javascript, url, timeout=120)
        subdomain_task = run_sync_with_timeout(discover_subdomains, url, timeout=120)

        # ---- Async modules (directly awaited) ----
        # crawl_website is async, so we call it directly
        crawl_task = asyncio.create_task(crawl_website(url))
        screenshot_task = asyncio.create_task(capture_screenshot(url))

        # Wait for all tasks
        ssl_result, security_result, ports_result, firewall_result, tech_result, js_result, subdomain_result = await asyncio.gather(
            ssl_task, security_task, ports_task, firewall_task, tech_task, js_task, subdomain_task,
            return_exceptions=True
        )

        crawl_result = await crawl_task
        screenshot_result = await screenshot_task

        # Build final result
        result = {
            "url": url,
            "ssl": safe_result(ssl_result),
            "security_headers": safe_result(security_result),
            "ports": safe_result(ports_result),
            "screenshot": safe_result(screenshot_result),
            "firewall": safe_result(firewall_result),
            "tech": safe_result(tech_result),
            "crawl": safe_result(crawl_result),
            "subdomains": safe_result(subdomain_result),
            "js_scanner": safe_result(js_result),
        }

        scan_id = await save_scan(url, result)
        result["scan_id"] = scan_id
        return result

    except Exception as e:
        print(f"[Scan] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history")
async def get_history():
    return await get_all_scans()

@router.get("/history/{scan_id}")
async def get_history_item(scan_id: str):
    return await get_scan_by_id(scan_id)

# ---- Individual endpoints (optional) ----
@router.post("/ssl")
async def api_ssl(payload: ScanRequest):
    return await asyncio.to_thread(analyze_ssl, payload.url)

@router.post("/security-headers")
async def api_security(payload: ScanRequest):
    return await asyncio.to_thread(analyze_security_headers, payload.url)

@router.post("/ports")
async def api_ports(payload: ScanRequest):
    return await asyncio.to_thread(scan_ports, payload.url, payload.port_option, payload.custom_ports)

@router.post("/screenshot")
async def api_screenshot(payload: ScanRequest):
    return await capture_screenshot(payload.url)

@router.post("/firewall")
async def api_firewall(payload: ScanRequest):
    return await asyncio.to_thread(detect_firewall, payload.url)

@router.post("/tech")
async def api_tech(payload: ScanRequest):
    return await asyncio.to_thread(detect_technologies, payload.url)

@router.post("/crawl")
async def api_crawl(payload: ScanRequest):
    return await crawl_website(payload.url)

@router.post("/js-scan")
async def api_js_scan(payload: ScanRequest):
    return await asyncio.to_thread(scan_javascript, payload.url)

@router.post("/subdomains")
async def api_subdomains(payload: ScanRequest):
    return await asyncio.to_thread(discover_subdomains, payload.url)

@router.post("/export-pdf")
async def export_pdf(payload: dict):
    try:
        from app.report.pdf_generator import generate_pdf_report
        filepath = await asyncio.to_thread(generate_pdf_report, payload, payload.get('url', 'unknown'))
        return {"success": True, "filepath": filepath, "download_url": f"/{filepath}"}
    except Exception as e:
        return {"success": False, "error": str(e)}