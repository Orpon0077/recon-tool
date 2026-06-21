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
    """Full scan with all modules - Optimized for Speed & Accuracy"""
    try:
        url = payload.url
        
        async def run_sync_with_timeout(func, *args, timeout=25):
            try:
                return await asyncio.wait_for(asyncio.to_thread(func, *args), timeout=timeout)
            except asyncio.TimeoutError:
                return {"error": "Timeout"}
        
        async def run_async_with_timeout(func, *args, timeout=25):
            try:
                return await asyncio.wait_for(func(*args), timeout=timeout)
            except asyncio.TimeoutError:
                return {"error": "Timeout"}
        
        # ── Fast Modules ──
        ssl_task = run_sync_with_timeout(analyze_ssl, url, timeout=25)
        security_task = run_sync_with_timeout(analyze_security_headers, url, timeout=25)
        firewall_task = run_sync_with_timeout(detect_firewall, url, timeout=25)
        tech_task = run_sync_with_timeout(detect_technologies, url, timeout=20)
        
        # ── Crawling (30s timeout for JS-rendered sites) ──
        crawl_task = run_sync_with_timeout(crawl_website, url, timeout=60)
        
        # ── Subdomain Discovery (50s timeout for Subfinder) ──
        subdomain_task = run_sync_with_timeout(discover_subdomains, url, timeout=50)
        
        # ── JS Scanner (18s timeout) ──
        js_task = run_sync_with_timeout(scan_javascript, url, timeout=25)
        
        # ── Port Scan (30s timeout for All Ports) ──
        ports_task = run_sync_with_timeout(scan_ports, url, payload.port_option, payload.custom_ports, timeout=60)
        
        # ── Screenshot (45s timeout, runs independently) ──
        screenshot_task = asyncio.create_task(run_async_with_timeout(capture_screenshot, url, timeout=60))
        
        # ── Gather all modules (except screenshot) ──
        ssl_result, security_result, firewall_result, tech_result, crawl_result, subdomain_result, js_result, ports_result = await asyncio.gather(
            ssl_task, security_task, firewall_task, tech_task, crawl_task, subdomain_task, js_task, ports_task,
            return_exceptions=True
        )
        
        # ── Wait for screenshot separately ──
        screenshot_result = await screenshot_task
        
        # ── Handle exceptions ──
        if isinstance(ssl_result, Exception):
            ssl_result = {"error": str(ssl_result)}
        if isinstance(security_result, Exception):
            security_result = {"error": str(security_result)}
        if isinstance(firewall_result, Exception):
            firewall_result = {"error": str(firewall_result)}
        if isinstance(tech_result, Exception):
            tech_result = {"error": str(tech_result)}
        if isinstance(crawl_result, Exception):
            crawl_result = {"error": str(crawl_result)}
        if isinstance(subdomain_result, Exception):
            subdomain_result = {"error": str(subdomain_result)}
        if isinstance(js_result, Exception):
            js_result = {"error": str(js_result)}
        if isinstance(ports_result, Exception):
            ports_result = {"error": str(ports_result)}
        if isinstance(screenshot_result, Exception):
            screenshot_result = {"error": str(screenshot_result)}
        
        # ── Prepare final result ──
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
        
        # ── Save to database ──
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


# ── PDF Report Export ──────────────────────────────────────
@router.post("/export-pdf")
async def export_pdf(payload: dict):
    """Generate PDF report from scan data"""
    try:
        from app.modules.pdf_generator import generate_pdf_report
        filepath = await asyncio.to_thread(generate_pdf_report, payload, payload.get('url', 'unknown'))
        return {"success": True, "filepath": filepath, "download_url": f"/{filepath}"}
    except Exception as e:
        return {"success": False, "error": str(e)}