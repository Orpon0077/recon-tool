from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict
import uuid
import re
import asyncio
from app.llm.system_prompt import SYSTEM_PROMPT
from app.llm.memory import conversation_memory
from app.llm.provider import llm_provider
from app.llm.reasoning import format_with_reasoning, get_reasoning
from app.llm.tools import TOOLS
from app.database.db import get_all_scans

router = APIRouter(prefix="/api/llm", tags=["llm"])

class ChatRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    session_id: str
    tool_calls: List[Dict] = []
    scan_id: Optional[str] = None

# ── Improved Intent Detection ──
def detect_intent(prompt: str):
    prompt_lower = prompt.lower()
    url_match = re.search(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', prompt)
    
    if not url_match:
        return None, None
    
    url = url_match.group(0)
    
    # ── Check for EXACT match keywords (more specific first) ──
    # Firewall specific
    if "firewall" in prompt_lower or "waf" in prompt_lower:
        return "firewall", url
    
    # SSL specific
    if "ssl" in prompt_lower or "certificate" in prompt_lower:
        return "ssl", url
    
    # Security headers specific
    if "security header" in prompt_lower or "header" in prompt_lower:
        return "security", url
    
    # Port specific
    if "port" in prompt_lower:
        return "ports", url
    
    # Subdomain specific
    if "subdomain" in prompt_lower:
        return "subdomains", url
    
    # Tech specific
    if "tech" in prompt_lower or "technology" in prompt_lower:
        return "tech", url
    
    # Crawl specific
    if "crawl" in prompt_lower or "endpoint" in prompt_lower:
        return "crawl", url
    
    # JS specific
    if "js" in prompt_lower or "javascript" in prompt_lower:
        return "js", url
    
    # Screenshot specific
    if "screenshot" in prompt_lower or "visual" in prompt_lower:
        return "screenshot", url
    
    # ── If user says "full scan" or "complete scan" or "all" ──
    if "full" in prompt_lower or "complete" in prompt_lower or "all" in prompt_lower:
        return "full", url
    
    # ── Default: Ask user what they want (safe) ──
    return "ask", url

# ── Execute specific scan only ──
async def execute_specific_scan(intent: str, url: str) -> dict:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"[LLM] 🔍 Executing {intent} scan: {url}")
    
    try:
        result = {}
        scan_id = None
        
        if intent == "full":
            from app.security.ssl import analyze_ssl
            from app.security.headers import analyze_security_headers
            from app.port_scanner.scanner import scan_ports
            from app.screenshot.capture import capture_screenshot
            from app.firewall.detection import detect_firewall
            from app.tech.detection import detect_technologies
            from app.crawl.crawler import crawl_website
            from app.js_scanner.scanner import scan_javascript
            from app.subdomain.discovery import discover_subdomains
            from app.database.db import save_scan
            
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
        
        elif intent == "firewall":
            from app.firewall.detection import detect_firewall
            result = {"firewall": (await asyncio.to_thread(detect_firewall, url)).dict()}
        
        elif intent == "ssl":
            from app.security.ssl import analyze_ssl
            result = {"ssl": (await asyncio.to_thread(analyze_ssl, url)).dict()}
        
        elif intent == "security":
            from app.security.headers import analyze_security_headers
            result = {"security_headers": (await asyncio.to_thread(analyze_security_headers, url)).dict()}
        
        elif intent == "ports":
            from app.port_scanner.scanner import scan_ports
            result = {"ports": (await asyncio.to_thread(scan_ports, url)).dict()}
        
        elif intent == "subdomains":
            from app.subdomain.discovery import discover_subdomains
            result = {"subdomains": await asyncio.to_thread(discover_subdomains, url)}
        
        elif intent == "tech":
            from app.tech.detection import detect_technologies
            result = {"tech": (await asyncio.to_thread(detect_technologies, url)).dict()}
        
        elif intent == "crawl":
            from app.crawl.crawler import crawl_website
            result = {"crawl": (await asyncio.to_thread(crawl_website, url)).dict()}
        
        elif intent == "js":
            from app.js_scanner.scanner import scan_javascript
            result = {"js_scanner": await asyncio.to_thread(scan_javascript, url)}
        
        elif intent == "screenshot":
            from app.screenshot.capture import capture_screenshot
            result = {"screenshot": (await capture_screenshot(url)).dict()}
        
        return {"success": True, "scan_id": scan_id, "result": result}
        
    except Exception as e:
        print(f"[LLM] ❌ Scan error: {e}")
        return {"success": False, "error": str(e)}

# ── Main Chat Endpoint ──
@router.post("/chat")
async def chat(request: ChatRequest):
    session_id = request.session_id or str(uuid.uuid4())
    prompt = request.prompt
    
    print(f"[LLM] 📩 Prompt: {prompt}")
    
    # ── Detect intent ──
    intent, url = detect_intent(prompt)
    
    # ── If "ask" -> ask user what they want ──
    if intent == "ask" and url:
        response = f"I found a URL ({url}). What would you like me to scan?\n\n"
        response += "Options:\n"
        response += "1. Full scan (all modules)\n"
        response += "2. Firewall / WAF detection\n"
        response += "3. SSL certificate\n"
        response += "4. Security headers\n"
        response += "5. Port scan\n"
        response += "6. Subdomains\n"
        response += "7. Technologies\n"
        response += "8. Crawl endpoints\n"
        response += "9. JavaScript files\n"
        response += "10. Screenshot\n\n"
        response += "Example: 'scan firewall of axiler.com'"
        
        conversation_memory.add_message(session_id, "user", prompt)
        conversation_memory.add_message(session_id, "assistant", response)
        return ChatResponse(response=response, session_id=session_id, tool_calls=[], scan_id=None)
    
    # ── If scan intent detected ──
    if intent and url:
        print(f"[LLM] 🎯 Intent: {intent}, URL: {url}")
        
        result = await execute_specific_scan(intent, url)
        
        if result.get("success"):
            reasoning = get_reasoning(intent, url)
            formatted = format_with_reasoning(intent, result.get("result", {}), reasoning)
            
            conversation_memory.add_message(session_id, "user", prompt)
            conversation_memory.add_message(session_id, "assistant", formatted)
            
            return ChatResponse(
                response=formatted,
                session_id=session_id,
                tool_calls=[{"tool": f"scan_{intent}", "arguments": {"url": url}}],
                scan_id=result.get("scan_id")
            )
        else:
            error_msg = f"❌ Scan failed: {result.get('error', 'Unknown error')}"
            conversation_memory.add_message(session_id, "user", prompt)
            conversation_memory.add_message(session_id, "assistant", error_msg)
            return ChatResponse(
                response=error_msg,
                session_id=session_id,
                tool_calls=[],
                scan_id=None
            )
    
    # ── History request ──
    if "history" in prompt.lower():
        scans = await get_all_scans()
        if scans:
            response = "RECENT SCANS:\n"
            for i, s in enumerate(scans[:10], 1):
                response += f"{i}. {s.get('url')} - {s.get('timestamp')}\n"
        else:
            response = "No scans found."
        
        conversation_memory.add_message(session_id, "user", prompt)
        conversation_memory.add_message(session_id, "assistant", response)
        return ChatResponse(response=response, session_id=session_id, tool_calls=[], scan_id=None)
    
    # ── Default: LLM response ──
    history = conversation_memory.get_context(session_id, max_messages=10)
    
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT}
    ]
    
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    
    messages.append({"role": "user", "content": prompt})
    
    response_text = await llm_provider.chat(messages)
    
    conversation_memory.add_message(session_id, "user", prompt)
    conversation_memory.add_message(session_id, "assistant", response_text)
    
    return ChatResponse(
        response=response_text,
        session_id=session_id,
        tool_calls=[],
        scan_id=None
    )
