from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict
import re
import asyncio
from app.database import get_all_scans, get_scan_by_id
from app.modules import (
    analyze_ssl, analyze_security_headers, scan_ports,
    capture_screenshot, detect_firewall, detect_technologies,
    crawl_website, scan_javascript, discover_subdomains
)

router = APIRouter(prefix="/api/llm", tags=["llm"])

class LLMRequest(BaseModel):
    prompt: str

class LLMResponse(BaseModel):
    response: str
    tool_calls: List[Dict] = []
    results: Dict = {}

async def execute_scan(url: str) -> Dict:
    """Full scan execution"""
    url = url.replace("https://", "").replace("http://", "").split("/")[0]
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"[LLM] Scanning: {url}")
    
    ssl = await asyncio.to_thread(analyze_ssl, url)
    security = await asyncio.to_thread(analyze_security_headers, url)
    ports = await asyncio.to_thread(scan_ports, url)
    screenshot = await capture_screenshot(url)
    firewall = await asyncio.to_thread(detect_firewall, url)
    tech = await asyncio.to_thread(detect_technologies, url)
    crawl = await asyncio.to_thread(crawl_website, url)
    js = await asyncio.to_thread(scan_javascript, url)
    subdomains = await asyncio.to_thread(discover_subdomains, url)
    
    return {
        "url": url,
        "ssl": ssl.dict() if hasattr(ssl, 'dict') else ssl,
        "security_headers": security.dict() if hasattr(security, 'dict') else security,
        "ports": ports.dict() if hasattr(ports, 'dict') else ports,
        "screenshot": screenshot.dict() if hasattr(screenshot, 'dict') else screenshot,
        "firewall": firewall.dict() if hasattr(firewall, 'dict') else firewall,
        "tech": tech.dict() if hasattr(tech, 'dict') else tech,
        "crawl": crawl.dict() if hasattr(crawl, 'dict') else crawl,
        "js_scanner": js if isinstance(js, dict) else js.dict() if hasattr(js, 'dict') else js,
        "subdomains": subdomains if isinstance(subdomains, dict) else subdomains.dict() if hasattr(subdomains, 'dict') else subdomains
    }

@router.post("/chat")
async def llm_chat(request: LLMRequest):
    prompt = request.prompt.lower()
    results = {}
    tool_calls = []
    
    print(f"[LLM] Prompt: {request.prompt}")
    
    # ── Intent Detection ──
    if "scan" in prompt or "recon" in prompt or "analyze" in prompt:
        url_match = re.search(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', request.prompt)
        
        if url_match:
            url = url_match.group(0)
            result = await execute_scan(url)
            results = result
            
            response = f"🔍 **Scan Complete for {url}**\n\n"
            response += f"📊 **Summary:**\n"
            response += f"• SSL: {result.get('ssl', {}).get('issued_to', 'N/A')}\n"
            response += f"• Security Score: {result.get('security_headers', {}).get('score', 0)}/100\n"
            response += f"• Open Ports: {result.get('ports', {}).get('total_open', 0)}\n"
            response += f"• Subdomains: {result.get('subdomains', {}).get('total_found', 0)}\n"
            response += f"• Technologies: {result.get('tech', {}).get('total_found', 0)}\n"
            
            tool_calls.append({"tool": "scan_website", "arguments": {"url": url}})
        else:
            response = "❌ Could not find a URL. Please provide a URL like 'scan axiler.com'"
    
    elif "history" in prompt:
        scans = await get_all_scans()
        if scans:
            response = "📋 **Recent Scans:**\n"
            for i, s in enumerate(scans[:10], 1):
                response += f"{i}. {s.get('url')} - {s.get('timestamp')}\n"
        else:
            response = "📋 No scans found. Run a scan first!"
    
    elif "pdf" in prompt or "export" in prompt:
        url_match = re.search(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', request.prompt)
        if url_match:
            url = url_match.group(0)
            from app.modules.pdf_generator import generate_pdf_report
            scans = await get_all_scans()
            for s in scans:
                if s.get('url') == url:
                    full_scan = await get_scan_by_id(s['id'])
                    if full_scan:
                        filepath = await asyncio.to_thread(generate_pdf_report, full_scan.get('results', {}), url)
                        response = f"✅ **PDF Report generated!**\n{filepath}"
                        results = {"pdf_url": f"/{filepath}"}
                        break
            else:
                response = f"❌ No scan found for {url}. Please run a scan first!"
        else:
            response = "❌ Please provide a URL like 'export PDF for axiler.com'"
    
    else:
        response = """🤖 **I'm your Recon Assistant!**

I can help you with:
1. **Scan a website**: "Scan axiler.com"
2. **View history**: "Show scan history"
3. **Export PDF**: "Export PDF for axiler.com"

Try one of these commands!"""
    
    return LLMResponse(
        response=response,
        tool_calls=tool_calls,
        results=results
    )
