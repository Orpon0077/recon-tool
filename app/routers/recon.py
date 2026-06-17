import asyncio
from fastapi import APIRouter, HTTPException
from app.models import (
    ScanRequest, FullReport, SSLResult, SecurityHeadersResult,
    PortScanResult, ScreenshotResult, FirewallResult,
    TechDetectionResult, CrawlResult, JSScanResult, SubdomainResult
)
from app.modules import (
    analyze_ssl,
    analyze_security_headers,
    scan_ports,
    capture_screenshot,
    detect_firewall,
    detect_technologies,
    crawl_website,
    scan_javascript,
    discover_subdomains
)
from app.database import save_scan, get_all_scans, get_scan_by_id

router = APIRouter(prefix="/api", tags=["recon"])

@router.post("/scan")
async def api_full_scan(payload: ScanRequest) -> dict:
    """Full scan with all modules"""
    try:
        url = payload.url
        
        async def run_sync_with_timeout(func, *args, timeout=15):
            try:
                return await asyncio.wait_for(asyncio.to_thread(func, *args), timeout=timeout)
            except asyncio.TimeoutError:
                return {"error": "Timeout"}
        
        async def run_async_with_timeout(func, *args, timeout=15):
            try:
                return await asyncio.wait_for(func(*args), timeout=timeout)
            except asyncio.TimeoutError:
                return {"error": "Timeout"}
        
        # Run all modules
        ssl_task = run_sync_with_timeout(analyze_ssl, url, timeout=10)
        security_task = run_sync_with_timeout(analyze_security_headers, url, timeout=10)
        ports_task = run_sync_with_timeout(scan_ports, url, payload.port_option, payload.custom_ports, timeout=20)
        screenshot_task = run_async_with_timeout(capture_screenshot, url, timeout=50)  # ← 50 seconds
        firewall_task = run_sync_with_timeout(detect_firewall, url, timeout=10)
        tech_task = run_sync_with_timeout(detect_technologies, url, timeout=15)
        crawl_task = run_sync_with_timeout(crawl_website, url, timeout=15)
        subdomain_task = run_sync_with_timeout(discover_subdomains, url, timeout=10)
        js_task = run_sync_with_timeout(scan_javascript, url, timeout=15)
        
        results = await asyncio.gather(
            ssl_task, security_task, ports_task, screenshot_task, 
            firewall_task, tech_task, crawl_task, subdomain_task, js_task,
            return_exceptions=True
        )
        
        ssl_result, security_result, ports_result, screenshot_result, firewall_result, tech_result, crawl_result, subdomain_result, js_result = results
        
        result = {
            "url": url,
            "ssl": ssl_result.dict() if hasattr(ssl_result, 'dict') else ssl_result,
            "security_headers": security_result.dict() if hasattr(security_result, 'dict') else security_result,
            "ports": ports_result.dict() if hasattr(ports_result, 'dict') else ports_result,
            "screenshot": screenshot_result.dict() if hasattr(screenshot_result, 'dict') else screenshot_result,
            "firewall": firewall_result.dict() if hasattr(firewall_result, 'dict') else firewall_result,
            "tech": tech_result.dict() if hasattr(tech_result, 'dict') else tech_result,
            "crawl": crawl_result.dict() if hasattr(crawl_result, 'dict') else crawl_result,
            "subdomains": subdomain_result.dict() if hasattr(subdomain_result, 'dict') else subdomain_result,
            "js_scanner": js_result.dict() if hasattr(js_result, 'dict') else js_result
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
        from app.modules.pdf_generator import generate_pdf_report
        filepath = await asyncio.to_thread(generate_pdf_report, payload, payload.get('url', 'unknown'))
        return {"success": True, "filepath": filepath, "download_url": f"/{filepath}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
