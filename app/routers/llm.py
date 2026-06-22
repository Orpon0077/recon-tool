# ── LLM Router (Enhanced) ──────────────────────────────────
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import re
import asyncio
import uuid
import json
from app.database import get_all_scans, get_scan_by_id, save_scan
from app.modules import (
    analyze_ssl, analyze_security_headers, scan_ports,
    capture_screenshot, detect_firewall, detect_technologies,
    crawl_website, scan_javascript, discover_subdomains
)
from app.llm_provider import llm_provider
from app.llm_memory import conversation_memory
from app.llm_tools import TOOLS

router = APIRouter(prefix="/api/llm", tags=["llm"])

class ChatRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    session_id: str
    tool_calls: List[Dict] = []
    scan_id: Optional[str] = None

# ── Tool Executor ──
async def execute_tool(tool_name: str, arguments: Dict) -> Dict:
    """Execute a tool call"""
    
    if tool_name == "scan_website":
        url = arguments.get("url")
        url = url.replace("https://", "").replace("http://", "").split("/")[0]
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"[LLM] Executing scan: {url}")
        
        # Run all modules
        ssl = await asyncio.to_thread(analyze_ssl, url)
        security = await asyncio.to_thread(analyze_security_headers, url)
        ports = await asyncio.to_thread(scan_ports, url)
        screenshot = await capture_screenshot(url)
        firewall = await asyncio.to_thread(detect_firewall, url)
        tech = await asyncio.to_thread(detect_technologies, url)
        crawl = await asyncio.to_thread(crawl_website, url)
        js = await asyncio.to_thread(scan_javascript, url)
        subdomains = await asyncio.to_thread(discover_subdomains, url)
        
        result = {
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
        
        # Save to database
        scan_id = await save_scan(url, result)
        
        return {
            "success": True,
            "scan_id": scan_id,
            "result": result
        }
    
    elif tool_name == "get_scan_history":
        limit = arguments.get("limit", 20)
        scans = await get_all_scans()
        return {"success": True, "scans": scans[:limit]}
    
    elif tool_name == "export_pdf_report":
        url = arguments.get("url")
        from app.modules.pdf_generator import generate_pdf_report
        scans = await get_all_scans()
        for s in scans:
            if s.get('url') == url:
                full_scan = await get_scan_by_id(s['id'])
                if full_scan:
                    filepath = await asyncio.to_thread(generate_pdf_report, full_scan.get('results', {}), url)
                    return {"success": True, "pdf_url": f"/{filepath}"}
        return {"success": False, "error": "No scan found"}
    
    return {"success": False, "error": f"Unknown tool: {tool_name}"}

# ── Format Response (No Emojis) ──
def format_scan_response(result: Dict, scan_id: str) -> str:
    """Format scan result as readable text - No Emojis"""
    url = result.get("url", "Unknown")
    
    response = f"SCAN COMPLETE for {url}\n\n"
    response += f"SUMMARY:\n"
    
    # SSL
    ssl = result.get("ssl", {})
    response += f"- SSL: {ssl.get('issued_to', 'N/A')} ({ssl.get('days_remaining', 0)} days left)\n"
    
    # Security Headers
    security = result.get("security_headers", {})
    score = security.get("score", 0)
    status = "GOOD" if score >= 70 else "MEDIUM" if score >= 40 else "POOR"
    response += f"- Security Score: {score}/100 ({status})\n"
    
    # Ports
    ports = result.get("ports", {})
    response += f"- Open Ports: {ports.get('total_open', 0)}\n"
    
    # Subdomains
    subdomains = result.get("subdomains", {})
    response += f"- Subdomains: {subdomains.get('total_found', 0)}\n"
    
    # Technologies
    tech = result.get("tech", {})
    response += f"- Technologies: {tech.get('total_found', 0)}\n"
    
    # Endpoints
    crawl = result.get("crawl", {})
    response += f"- Endpoints: {crawl.get('total_found', 0)}\n"
    
    # JS Files
    js = result.get("js_scanner", {})
    response += f"- JS Files: {js.get('total_js_files', 0)}\n"
    
    # Firewall
    firewall = result.get("firewall", {})
    if firewall.get("detected"):
        response += f"- Firewall: {firewall.get('firewall_name', 'Unknown')}\n"
    else:
        response += f"- Firewall: Not Detected\n"
    
    response += f"\nScan ID: {scan_id}\n"
    response += f"View Dashboard: http://localhost:8000/?scan_id={scan_id}\n"
    
    return response

# ── Chat Endpoint ──
@router.post("/chat")
async def chat(request: ChatRequest):
    """Enhanced chat with LLM"""
    
    # Generate or use session ID
    session_id = request.session_id or str(uuid.uuid4())
    
    # Get conversation history
    history = conversation_memory.get_context(session_id, max_messages=10)
    
    # Prepare messages
    messages = [
        {
            "role": "system",
            "content": """You are Recon Assistant, a web reconnaissance expert.
You help users scan websites for security, technology, and infrastructure information.

Available tools:
1. scan_website(url) - Full website scan (SSL, security, ports, subdomains, tech, crawl)
2. get_scan_history(limit) - Get previous scans
3. export_pdf_report(url) - Generate PDF report

Guidelines:
- Be helpful and concise
- Do not use emojis in your responses
- Always confirm before scanning
- Summarize results clearly
- Suggest next steps based on findings
- If user asks about security, explain the risks
- Be professional but friendly"""
        }
    ]
    
    # Add history
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    
    # Add current prompt
    messages.append({"role": "user", "content": request.prompt})
    
    # Store user message
    conversation_memory.add_message(session_id, "user", request.prompt)
    
    # ── Call LLM ──
    response_data = await llm_provider.chat(messages, tools=TOOLS)
    
    # ── Check for tool calls ──
    tool_calls = []
    scan_id = None
    final_response = ""
    
    if "error" in response_data:
        # Fallback: Rule-based if LLM fails
        final_response = await rule_based_fallback(request.prompt)
    else:
        # Parse LLM response
        try:
            choice = response_data.get("choices", [{}])[0]
            message = choice.get("message", {})
            
            # Check for tool calls
            if "tool_calls" in message and message["tool_calls"]:
                for tool_call in message["tool_calls"]:
                    tool_name = tool_call.get("function", {}).get("name")
                    arguments = json.loads(tool_call.get("function", {}).get("arguments", "{}"))
                    
                    tool_calls.append({"tool": tool_name, "arguments": arguments})
                    
                    # Execute tool
                    result = await execute_tool(tool_name, arguments)
                    
                    if result.get("success"):
                        if tool_name == "scan_website":
                            scan_id = result.get("scan_id")
                            final_response = format_scan_response(result.get("result", {}), scan_id)
                        elif tool_name == "get_scan_history":
                            scans = result.get("scans", [])
                            if scans:
                                final_response = "Recent Scans:\n"
                                for i, s in enumerate(scans[:10], 1):
                                    final_response += f"{i}. {s.get('url')} - {s.get('timestamp')}\n"
                            else:
                                final_response = "No scans found."
                        elif tool_name == "export_pdf_report":
                            pdf_url = result.get("pdf_url")
                            if pdf_url:
                                final_response = f"PDF Report generated successfully.\nDownload: {pdf_url}"
                            else:
                                final_response = "No scan found for this URL."
                    else:
                        final_response = f"Tool execution failed: {result.get('error', 'Unknown error')}"
            else:
                # No tool call, just return the response
                final_response = message.get("content", "I didn't understand that.")
        except Exception as e:
            final_response = f"Error processing response: {e}"
    
    # Store assistant response
    conversation_memory.add_message(session_id, "assistant", final_response)
    
    return ChatResponse(
        response=final_response,
        session_id=session_id,
        tool_calls=tool_calls,
        scan_id=scan_id
    )

# ── Rule-based Fallback (if LLM fails) ──
async def rule_based_fallback(prompt: str) -> str:
    """Fallback when LLM is not available - No Emojis"""
    prompt_lower = prompt.lower()
    
    if "scan" in prompt_lower or "recon" in prompt_lower:
        url_match = re.search(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', prompt)
        if url_match:
            url = url_match.group(0)
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Execute scan directly
            ssl = await asyncio.to_thread(analyze_ssl, url)
            security = await asyncio.to_thread(analyze_security_headers, url)
            ports = await asyncio.to_thread(scan_ports, url)
            screenshot = await capture_screenshot(url)
            firewall = await asyncio.to_thread(detect_firewall, url)
            tech = await asyncio.to_thread(detect_technologies, url)
            crawl = await asyncio.to_thread(crawl_website, url)
            js = await asyncio.to_thread(scan_javascript, url)
            subdomains = await asyncio.to_thread(discover_subdomains, url)
            
            result = {
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
            
            scan_id = await save_scan(url, result)
            return format_scan_response(result, scan_id)
        else:
            return "Could not find a URL. Please provide a URL like 'scan axiler.com'"
    
    elif "history" in prompt_lower:
        scans = await get_all_scans()
        if scans:
            response = "Recent Scans:\n"
            for i, s in enumerate(scans[:10], 1):
                response += f"{i}. {s.get('url')} - {s.get('timestamp')}\n"
            return response
        return "No scans found."
    
    return """I am your Recon Assistant.

I can help you with:
1. Scan a website: "Scan axiler.com"
2. View history: "Show scan history"
3. Export PDF: "Export PDF for axiler.com"

Try one of these commands."""

# ── Clear Session ──
@router.post("/clear")
async def clear_session(session_id: str):
    """Clear conversation history"""
    conversation_memory.clear_session(session_id)
    return {"status": "cleared", "session_id": session_id}
