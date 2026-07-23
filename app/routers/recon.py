import asyncio
import socket
from urllib.parse import urlparse

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
from app.subdomain.discovery import discover_subdomains, merge_subdomain_lists
from app.database.db import save_scan, get_all_scans, get_scan_by_id

from app.osint.collector import OSINTCollector
from app.prioritization.risk_score import calculate_risk
from app.threat_intel import ThreatIntelCollector

router = APIRouter(prefix="/api", tags=["recon"])


@router.post("/scan")
async def api_full_scan(payload: ScanRequest) -> dict:
    """
    Full scan with all modules – all sync modules run via asyncio.to_thread.
    Timeouts are set to extremely high values to ensure completion.
    """
    try:
        url = payload.url

        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
        domain = parsed.netloc or url

        async def run_sync_with_timeout(func, *args, timeout=600):
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(func, *args),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                return {"error": f"Timeout after {timeout}s"}

        async def run_async_with_timeout(func, *args, timeout=600):
            try:
                return await asyncio.wait_for(
                    func(*args),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                return {"error": f"Timeout after {timeout}s"}

        ssl_task = run_sync_with_timeout(analyze_ssl, url, timeout=120)
        security_task = run_sync_with_timeout(analyze_security_headers, url, timeout=120)
        firewall_task = run_sync_with_timeout(detect_firewall, url, timeout=90)
        tech_task = run_sync_with_timeout(detect_technologies, url, timeout=300)
        crawl_task = run_sync_with_timeout(crawl_website, url, timeout=7200)
        subdomain_task = run_sync_with_timeout(discover_subdomains, url, timeout=3600)
        js_task = run_sync_with_timeout(scan_javascript, url, timeout=300)
        ports_task = run_sync_with_timeout(
            scan_ports, url, payload.port_option, payload.custom_ports,
            timeout=600
        )
        screenshot_task = run_async_with_timeout(capture_screenshot, url, timeout=600)

        osint_collector = OSINTCollector(domain)
        osint_task = run_async_with_timeout(osint_collector.run_all, timeout=600)

        try:
            (
                ssl_result,
                security_result,
                firewall_result,
                tech_result,
                crawl_result,
                subdomain_result,
                js_result,
                ports_result,
                osint_result
            ) = await asyncio.wait_for(
                asyncio.gather(
                    ssl_task,
                    security_task,
                    firewall_task,
                    tech_task,
                    crawl_task,
                    subdomain_task,
                    js_task,
                    ports_task,
                    osint_task,
                    return_exceptions=True
                ),
                timeout=10800
            )
        except asyncio.TimeoutError:
            return {
                "url": url,
                "error": "Overall scan timed out after 3 hours. Partial results may be available.",
                "scan_id": None
            }

        screenshot_result = await screenshot_task

        def handle_result(result):
            if isinstance(result, Exception):
                return {"error": str(result)}
            if hasattr(result, 'dict'):
                return result.dict()
            if isinstance(result, dict):
                return result
            return result

        subdomain_payload = handle_result(subdomain_result)
        osint_payload = handle_result(osint_result)

        # ── বাংলা: crt.sh থেকে পাওয়া সাবডোমেইনগুলো source="crt.sh" দিয়ে মার্জ করি ──
        if isinstance(subdomain_payload, dict) and isinstance(osint_payload, dict):
            crt_hosts = osint_payload.get("crt_subdomains", [])
            if crt_hosts:
                crt_entries = [
                    {"subdomain": host, "ip": "N/A", "source": "crt.sh", "resolved": False}
                    for host in crt_hosts
                    if isinstance(host, str)
                ]
                existing = subdomain_payload.get("subdomains", [])
                merged = merge_subdomain_lists(existing, crt_entries)
                subdomain_payload["subdomains"] = merged
                subdomain_payload["total_found"] = len(merged)
                subdomain_payload["sensitive_count"] = sum(
                    1 for item in merged if item.get("sensitive")
                )

        result = {
            "url": url,
            "ssl": handle_result(ssl_result),
            "security_headers": handle_result(security_result),
            "ports": handle_result(ports_result),
            "screenshot": handle_result(screenshot_result),
            "firewall": handle_result(firewall_result),
            "tech": handle_result(tech_result),
            "crawl": handle_result(crawl_result),
            "subdomains": subdomain_payload,
            "js_scanner": handle_result(js_result),
            "osint": osint_payload,
        }

        # ── Threat Intelligence ──
        try:
            ips = []
            subs = subdomain_payload.get("subdomains", []) if isinstance(subdomain_payload, dict) else []
            for s in subs:
                if isinstance(s, dict):
                    ip = s.get("ip")
                    if ip and ip != "N/A":
                        ips.append(ip)

            try:
                main_ip = socket.gethostbyname(domain)
                ips.append(main_ip)
            except:
                pass

            sub_names = []
            for s in subs:
                if isinstance(s, dict):
                    name = s.get("subdomain")
                    if name:
                        sub_names.append(name)

            threat_collector = ThreatIntelCollector(domain, ips, sub_names)
            threat_result = await threat_collector.run()
            result["threat_intel"] = threat_result
        except Exception as e:
            result["threat_intel"] = {"error": str(e)}

        # ── Risk ──
        try:
            risk_result = await run_sync_with_timeout(calculate_risk, result, timeout=120)
        except Exception as exc:
            risk_result = {"error": f"Risk analysis failed: {exc}"}
        result["risk"] = handle_result(risk_result)

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


@router.post("/ssl")
async def api_ssl(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(analyze_ssl, payload.url)


@router.post("/security-headers")
async def api_security(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(analyze_security_headers, payload.url)


@router.post("/ports")
async def api_ports(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(
        scan_ports, payload.url, payload.port_option, payload.custom_ports
    )


@router.post("/screenshot")
async def api_screenshot(payload: ScanRequest) -> dict:
    return await capture_screenshot(payload.url)


@router.post("/firewall")
async def api_firewall(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(detect_firewall, payload.url)


@router.post("/tech")
async def api_tech(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(detect_technologies, payload.url)


@router.post("/crawl")
async def api_crawl(payload: ScanRequest) -> dict:
    return await asyncio.to_thread(crawl_website, payload.url)


@router.post("/js-scan")
async def api_js_scan(payload: ScanRequest) -> dict:
    result = await asyncio.to_thread(scan_javascript, payload.url)
    if result is None:
        return {"error": "JS scanner returned no data", "total_js_files": 0}
    if isinstance(result, dict) and "error" not in result:
        result.setdefault("total_js_files", 0)
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
        filepath = await asyncio.to_thread(
            generate_pdf_report,
            payload,
            payload.get('url', 'unknown')
        )
        return {
            "success": True,
            "filepath": filepath,
            "download_url": f"/{filepath}"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}