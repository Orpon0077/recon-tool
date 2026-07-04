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
from app.database.db import get_all_scans
from app.database.chat_history import get_all_conversations, delete_conversation

router = APIRouter(prefix="/api/llm", tags=["llm"])

class ChatRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    session_id: str
    tool_calls: List[Dict] = []
    scan_id: Optional[str] = None

# ── Quick responses ──
def get_quick_response(prompt: str) -> str:
    prompt_lower = prompt.lower()
    
    if prompt_lower in ["hello", "hi", "hey", "how are you"]:
        return "Hello! I am Recon Assistant. I can help you scan websites for security and infrastructure. Try 'Help' for more information."
    
    if "help" in prompt_lower:
        return """I can help you with:

1. Scan a website: "Full scan axiler.com"
2. Specific scans:
   - "Firewall of axiler.com"
   - "SSL of axiler.com"
   - "Subdomains of axiler.com"
   - "Crawl axiler.com"
   - "Tech of axiler.com"
   - "Ports of axiler.com"
   - "Security headers of axiler.com"
   - "JS of axiler.com"
   - "Screenshot of axiler.com"
3. History: "Show scan history"
4. PDF: "Export PDF for axiler.com"
5. Chat history: "Show chat history"

Try one of these commands."""
    
    return None

# ── Detect intent ──
def detect_intent(prompt: str):
    prompt_lower = prompt.lower()
    url_match = re.search(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', prompt)
    
    if not url_match:
        return None, None
    
    url = url_match.group(0)
    
    if "firewall" in prompt_lower or "waf" in prompt_lower:
        return "firewall", url
    if "ssl" in prompt_lower or "certificate" in prompt_lower:
        return "ssl", url
    if "security header" in prompt_lower or "header" in prompt_lower:
        return "security", url
    if "port" in prompt_lower:
        return "ports", url
    if "subdomain" in prompt_lower:
        return "subdomains", url
    if "tech" in prompt_lower or "technology" in prompt_lower:
        return "tech", url
    if "crawl" in prompt_lower or "endpoint" in prompt_lower:
        return "crawl", url
    if "js" in prompt_lower or "javascript" in prompt_lower:
        return "js", url
    if "screenshot" in prompt_lower or "visual" in prompt_lower:
        return "screenshot", url
    if "full" in prompt_lower or "complete" in prompt_lower or "all" in prompt_lower:
        return "full", url
    
    return "ask", url

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

@router.post("/chat")
async def chat(request: ChatRequest):
    session_id = request.session_id or str(uuid.uuid4())
    prompt = request.prompt
    
    print(f"[LLM] 📩 Prompt: {prompt}")
    
    # ── Quick response ──
    quick_response = get_quick_response(prompt)
    if quick_response:
        await conversation_memory.add_message(session_id, "user", prompt)
        await conversation_memory.add_message(session_id, "assistant", quick_response)
        return ChatResponse(
            response=quick_response,
            session_id=session_id,
            tool_calls=[],
            scan_id=None
        )
    
    # ── Chat history request ──
    if "chat history" in prompt.lower() or "conversation history" in prompt.lower():
        conversations = await get_all_conversations(limit=20)
        if conversations:
            response = "CHAT HISTORY:\n"
            for i, conv in enumerate(conversations, 1):
                response += f"{i}. Session: {conv.get('session_id', 'N/A')[:8]}... - {conv.get('message_count', 0)} messages - {conv.get('created_at', 'Unknown')}\n"
        else:
            response = "No chat history found."
        
        await conversation_memory.add_message(session_id, "user", prompt)
        await conversation_memory.add_message(session_id, "assistant", response)
        return ChatResponse(response=response, session_id=session_id, tool_calls=[], scan_id=None)
    
    # ── Detect intent ──
    intent, url = detect_intent(prompt)
    
    if intent == "ask" and url:
        response = f"I found URL: {url}. What would you like to scan?\n\nOptions: full, firewall, ssl, security headers, ports, subdomains, tech, crawl, js, screenshot\nExample: 'firewall of axiler.com'"
        
        await conversation_memory.add_message(session_id, "user", prompt)
        await conversation_memory.add_message(session_id, "assistant", response)
        return ChatResponse(response=response, session_id=session_id, tool_calls=[], scan_id=None)
    
    if intent and url:
        print(f"[LLM] 🎯 Intent: {intent}, URL: {url}")
        
        result = await execute_specific_scan(intent, url)
        
        if result.get("success"):
            reasoning = get_reasoning(intent, url)
            formatted = format_with_reasoning(intent, result.get("result", {}), reasoning)
            
            await conversation_memory.add_message(session_id, "user", prompt)
            await conversation_memory.add_message(session_id, "assistant", formatted)
            
            return ChatResponse(
                response=formatted,
                session_id=session_id,
                tool_calls=[{"tool": f"scan_{intent}", "arguments": {"url": url}}],
                scan_id=result.get("scan_id")
            )
        else:
            error_msg = f"❌ Scan failed: {result.get('error', 'Unknown error')}"
            await conversation_memory.add_message(session_id, "user", prompt)
            await conversation_memory.add_message(session_id, "assistant", error_msg)
            return ChatResponse(
                response=error_msg,
                session_id=session_id,
                tool_calls=[],
                scan_id=None
            )
    
    # ── Scan history ──
    if "history" in prompt.lower():
        scans = await get_all_scans()
        if scans:
            response = "RECENT SCANS:\n"
            for i, s in enumerate(scans[:10], 1):
                response += f"{i}. {s.get('url')} - {s.get('timestamp')}\n"
        else:
            response = "No scans found."
        
        await conversation_memory.add_message(session_id, "user", prompt)
        await conversation_memory.add_message(session_id, "assistant", response)
        return ChatResponse(response=response, session_id=session_id, tool_calls=[], scan_id=None)
    
    # ── Default: LLM response ──
    history = await conversation_memory.get_context(session_id, max_messages=5)
    
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT}
    ]
    
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    
    messages.append({"role": "user", "content": prompt})
    
    try:
        response_text = await asyncio.wait_for(llm_provider.chat(messages), timeout=30)
    except asyncio.TimeoutError:
        response_text = "The LLM server is taking too long. Please try again or use specific commands like 'Firewall of axiler.com'."
    
    await conversation_memory.add_message(session_id, "user", prompt)
    await conversation_memory.add_message(session_id, "assistant", response_text)
    
    return ChatResponse(
        response=response_text,
        session_id=session_id,
        tool_calls=[],
        scan_id=None
    )

# ── Delete chat history ──
@router.delete("/history/{session_id}")
async def delete_chat_history(session_id: str):
    result = await delete_conversation(session_id)
    if result:
        conversation_memory.clear_session(session_id)
        return {"status": "deleted", "session_id": session_id}
    return {"status": "not_found", "session_id": session_id}
