from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import uuid
import asyncio
import re
from datetime import datetime
from app.llm_provider import llm_provider

from app.port_scanner.scanner import scan_ports
from app.crawl.crawler import crawl_website
from app.subdomain.discovery import discover_subdomains
from app.tech.detection import detect_technologies
from app.security.ssl import analyze_ssl
from app.security.headers import analyze_headers
from app.firewall.detection import detect_firewall
from app.screenshot.capture import capture_screenshot
from app.js_scanner.scanner import scan_javascript

router = APIRouter(prefix="/api/llm", tags=["llm"])


class ChatRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    session_id: str
    provider: Optional[str] = None
    scan_id: Optional[str] = None


conversations = {}
conversation_history = {}


def extract_domain(prompt: str) -> Optional[str]:
    """Prompt থেকে domain বের করো"""
    # https:// বা http:// সহ URL থেকে domain
    url_match = re.search(
        r'https?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,})',
        prompt
    )
    if url_match:
        return url_match.group(1)

    # Bare domain (যেমন axiler.com, google.com)
    domain_match = re.search(
        r'\b([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b',
        prompt
    )
    if domain_match:
        candidate = domain_match.group(1)
        # এগুলো domain না — skip করো
        skip_words = {
            "example.com", "do", "of", "in", "on", "for", "the",
            "this", "that", "can", "you", "me", "my", "is", "it",
        }
        if candidate.lower() not in skip_words:
            return candidate

    return None


def detect_scan_intent(prompt: str) -> Optional[dict]:
    """User কী scan করতে চাইছে সেটা detect করো"""
    p = prompt.lower()
    domain = extract_domain(prompt)

    if not domain:
        return None

    # Specific scan types — order matters (more specific first)
    if any(w in p for w in ["full scan", "complete scan", "scan everything", "all modules", "full recon"]):
        return {"action": "full_scan", "target": domain}
    elif any(w in p for w in ["subdomain", "subdomains", "sub domain", "dns enum"]):
        return {"action": "subdomain", "target": domain}
    elif any(w in p for w in ["crawl", "crawling", "endpoint", "endpoints", "find urls", "discover urls", "find pages"]):
        return {"action": "crawl", "target": domain}
    elif any(w in p for w in ["tech", "technology", "technologies", "stack", "built with", "framework", "cms"]):
        return {"action": "tech", "target": domain}
    elif any(w in p for w in ["ssl", "certificate", "tls", "cert", "https check", "expiry"]):
        return {"action": "ssl", "target": domain}
    elif any(w in p for w in ["header", "headers", "security header", "hsts", "csp", "x-frame"]):
        return {"action": "headers", "target": domain}
    elif any(w in p for w in ["firewall", "waf", "cloudflare check", "waf detect", "ddos protection"]):
        return {"action": "firewall", "target": domain}
    elif any(w in p for w in ["screenshot", "capture", "visual", "look like", "see the site"]):
        return {"action": "screenshot", "target": domain}
    elif any(w in p for w in ["js scan", "javascript scan", "js analysis", "javascript analysis", "js file", "api key"]):
        return {"action": "js", "target": domain}
    elif any(w in p for w in ["port", "ports", "port scan", "open ports", "scan ports", "nmap"]):
        return {"action": "port_scan", "target": domain}
    elif any(w in p for w in ["scan", "check", "analyze", "analyse", "recon", "reconnaissance", "audit"]):
        # Generic scan request — full scan করো
        return {"action": "full_scan", "target": domain}

    return None


async def execute_scan(action: str, domain: str) -> dict:
    """Requested scan চালাও এবং result return করো"""
    try:
        if action == "full_scan":
            results_list = await asyncio.gather(
                asyncio.to_thread(scan_ports, f"https://{domain}", "top50"),
                crawl_website(f"https://{domain}"),
                asyncio.to_thread(discover_subdomains, domain),
                detect_technologies(f"https://{domain}"),
                asyncio.to_thread(analyze_ssl, f"https://{domain}"),
                asyncio.to_thread(analyze_headers, f"https://{domain}"),
                asyncio.to_thread(detect_firewall, f"https://{domain}"),
                scan_javascript(f"https://{domain}"),
                capture_screenshot(f"https://{domain}"),
                return_exceptions=True,
            )
            return {
                "type": "full_scan", "target": domain,
                "ports":      results_list[0] if not isinstance(results_list[0], Exception) else None,
                "crawl":      results_list[1] if not isinstance(results_list[1], Exception) else None,
                "subdomains": results_list[2] if not isinstance(results_list[2], Exception) else None,
                "tech":       results_list[3] if not isinstance(results_list[3], Exception) else None,
                "ssl":        results_list[4] if not isinstance(results_list[4], Exception) else None,
                "headers":    results_list[5] if not isinstance(results_list[5], Exception) else None,
                "firewall":   results_list[6] if not isinstance(results_list[6], Exception) else None,
                "js":         results_list[7] if not isinstance(results_list[7], Exception) else None,
                "screenshot": results_list[8] if not isinstance(results_list[8], Exception) else None,
                "scan_id": str(uuid.uuid4()),
            }

        elif action == "port_scan":
            result = await asyncio.to_thread(scan_ports, f"https://{domain}", "top50")
            return {"type": "port_scan", "target": domain, "data": result}

        elif action == "crawl":
            result = await crawl_website(f"https://{domain}")
            return {"type": "crawl", "target": domain, "data": result}

        elif action == "subdomain":
            result = await asyncio.to_thread(discover_subdomains, domain)
            return {"type": "subdomain", "target": domain, "data": result}

        elif action == "tech":
            result = await detect_technologies(f"https://{domain}")
            return {"type": "tech", "target": domain, "data": result}

        elif action == "ssl":
            result = await asyncio.to_thread(analyze_ssl, f"https://{domain}")
            return {"type": "ssl", "target": domain, "data": result}

        elif action == "headers":
            result = await asyncio.to_thread(analyze_headers, f"https://{domain}")
            return {"type": "headers", "target": domain, "data": result}

        elif action == "firewall":
            result = await asyncio.to_thread(detect_firewall, f"https://{domain}")
            return {"type": "firewall", "target": domain, "data": result}

        elif action == "screenshot":
            result = await capture_screenshot(f"https://{domain}")
            return {"type": "screenshot", "target": domain, "data": result}

        elif action == "js":
            result = await scan_javascript(f"https://{domain}")
            return {"type": "js", "target": domain, "data": result}

        else:
            return {"type": "unknown", "target": domain, "data": None}

    except Exception as e:
        return {"type": "error", "target": domain, "data": None, "error": str(e)}


def format_scan_results(scan_results: dict) -> str:
    """Scan results কে LLM readable text এ convert করো"""
    if not scan_results:
        return "No results available."

    scan_type = scan_results.get("type")
    target = scan_results.get("target")

    if scan_type == "port_scan":
        data = scan_results.get("data", {})
        if isinstance(data, dict):
            ports = data.get("open_ports", [])
        else:
            ports = []
        if ports:
            lines = [f"  Port {p['port']} | {p.get('service','unknown')} | {p.get('state','open')} | version: {p.get('version','unknown')}" for p in ports[:30]]
            return f"PORT SCAN — {target}\nOpen ports found: {len(ports)}\n" + "\n".join(lines)
        return f"PORT SCAN — {target}\nNo open ports found."

    elif scan_type == "crawl":
        data = scan_results.get("data", {})
        if isinstance(data, dict):
            endpoints = data.get("endpoints", data.get("urls", []))
        else:
            endpoints = data or []
        if endpoints:
            if endpoints and isinstance(endpoints[0], dict):
                lines = [f"  {e.get('url','')} | {e.get('method','GET')} | {e.get('status_code','?')} | {e.get('content_type','')}" for e in endpoints[:30]]
            else:
                lines = [f"  {e}" for e in endpoints[:30]]
            return f"CRAWL — {target}\nEndpoints found: {len(endpoints)}\n" + "\n".join(lines)
        return f"CRAWL — {target}\nNo endpoints found."

    elif scan_type == "subdomain":
        data = scan_results.get("data", {})
        if isinstance(data, dict):
            subs = data.get("subdomains", [])
            total = data.get("total_found", len(subs))
        else:
            subs = data or []
            total = len(subs)
        if subs:
            if subs and isinstance(subs[0], dict):
                lines = [f"  {s.get('subdomain','')} -> {s.get('ip','unknown')}" for s in subs[:30]]
            else:
                lines = [f"  {s}" for s in subs[:30]]
            return f"SUBDOMAIN DISCOVERY — {target}\nSubdomains found: {total}\n" + "\n".join(lines)
        return f"SUBDOMAIN DISCOVERY — {target}\nNo subdomains found."

    elif scan_type == "tech":
        data = scan_results.get("data", {})
        if isinstance(data, dict):
            techs = data.get("technologies", data)
            total = data.get("total_found", 0)
        else:
            techs = {}
            total = 0
        if techs and isinstance(techs, dict):
            lines = [f"  {cat}: {', '.join(items)}" for cat, items in techs.items()]
            return f"TECHNOLOGY DETECTION — {target}\nTotal found: {total}\n" + "\n".join(lines)
        return f"TECHNOLOGY DETECTION — {target}\nNo technologies detected."

    elif scan_type == "ssl":
        data = scan_results.get("data", {})
        if not data:
            return f"SSL ANALYSIS — {target}\nFailed to retrieve SSL data."
        return (
            f"SSL ANALYSIS — {target}\n"
            f"  Issued to: {data.get('issued_to', 'unknown')}\n"
            f"  Issued by: {data.get('issued_by', 'unknown')}\n"
            f"  Valid from: {data.get('valid_from', 'unknown')}\n"
            f"  Valid until: {data.get('valid_until', 'unknown')}\n"
            f"  Days remaining: {data.get('days_remaining', 'unknown')}\n"
            f"  Expired: {data.get('is_expired', False)}"
        )

    elif scan_type == "headers":
        data = scan_results.get("data", {})
        if not data:
            return f"SECURITY HEADERS — {target}\nFailed to retrieve header data."
        present = data.get("present", {})
        missing = data.get("missing", [])
        score = data.get("score", 0)
        present_lines = [f"  [PRESENT] {h}: {v[:80]}" for h, v in present.items()]
        missing_lines = [f"  [MISSING] {h}" for h in missing]
        return (
            f"SECURITY HEADERS — {target}\n"
            f"  Score: {score}/100\n"
            + "\n".join(present_lines)
            + ("\n" if present_lines else "")
            + "\n".join(missing_lines)
        )

    elif scan_type == "firewall":
        data = scan_results.get("data", {})
        if not data:
            return f"FIREWALL DETECTION — {target}\nFailed."
        if data.get("detected"):
            return (
                f"FIREWALL DETECTION — {target}\n"
                f"  Detected: YES\n"
                f"  Firewall: {data.get('firewall_name', 'Unknown')}\n"
                f"  Evidence: {data.get('evidence', 'unknown')}"
            )
        return (
            f"FIREWALL DETECTION — {target}\n"
            f"  Detected: NO\n"
            f"  Evidence: {data.get('evidence', 'No WAF signatures found')}"
        )

    elif scan_type == "screenshot":
        data = scan_results.get("data", {})
        if data and data.get("screenshot_path"):
            return f"SCREENSHOT — {target}\n  Captured and saved at: {data.get('screenshot_path')}"
        err = data.get("error", "Unknown error") if data else "Unknown error"
        return f"SCREENSHOT — {target}\n  Failed: {err}"

    elif scan_type == "js":
        data = scan_results.get("data", {})
        if not data:
            return f"JS ANALYSIS — {target}\n  No data."
        return (
            f"JS ANALYSIS — {target}\n"
            f"  JS files found: {data.get('total', 0)}\n"
            f"  Issues detected: {len(data.get('vulnerabilities', []))}"
        )

    elif scan_type == "full_scan":
        parts = [f"FULL SCAN — {target}"]
        if scan_results.get("ports"):
            p = scan_results["ports"]
            ports = p.get("open_ports", []) if isinstance(p, dict) else []
            parts.append(f"  Ports: {len(ports)} open")
        if scan_results.get("subdomains"):
            s = scan_results["subdomains"]
            total = s.get("total_found", 0) if isinstance(s, dict) else len(s or [])
            parts.append(f"  Subdomains: {total} found")
        if scan_results.get("tech"):
            t = scan_results["tech"]
            techs = t.get("technologies", {}) if isinstance(t, dict) else {}
            total = sum(len(v) for v in techs.values()) if isinstance(techs, dict) else 0
            parts.append(f"  Technologies: {total} found")
        if scan_results.get("ssl"):
            s = scan_results["ssl"]
            days = s.get("days_remaining", "unknown") if isinstance(s, dict) else "unknown"
            parts.append(f"  SSL: {days} days remaining")
        if scan_results.get("headers"):
            h = scan_results["headers"]
            score = h.get("score", 0) if isinstance(h, dict) else 0
            parts.append(f"  Security headers score: {score}/100")
        if scan_results.get("crawl"):
            c = scan_results["crawl"]
            endpoints = c.get("endpoints", c.get("urls", [])) if isinstance(c, dict) else (c or [])
            parts.append(f"  Endpoints crawled: {len(endpoints)}")
        if scan_results.get("firewall"):
            fw = scan_results["firewall"]
            if isinstance(fw, dict) and fw.get("detected"):
                parts.append(f"  Firewall: {fw.get('firewall_name', 'Detected')}")
            else:
                parts.append("  Firewall: Not detected")
        if scan_results.get("js"):
            js = scan_results["js"]
            total = js.get("total", 0) if isinstance(js, dict) else 0
            parts.append(f"  JS files analyzed: {total}")
        return "\n".join(parts)

    elif scan_type == "error":
        return f"SCAN ERROR — {target}\n  {scan_results.get('error', 'Unknown error')}"

    return "Scan completed but no data available."


@router.post("/chat")
async def chat(request: ChatRequest):
    print("[LLM_ROUTER] /chat endpoint hit!")
    print("[LLM_ROUTER] Prompt:", request.prompt)

    session_id = request.session_id or str(uuid.uuid4())

    if session_id not in conversations:
        conversations[session_id] = []
        conversation_history[session_id] = {
            "session_id": session_id,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "messages": [],
        }

    conversations[session_id].append({"role": "user", "content": request.prompt})

    scan_intent = detect_scan_intent(request.prompt)
    response_text = ""
    scan_id = None

    if scan_intent:
        action = scan_intent["action"]
        target = scan_intent["target"]
        print(f"[LLM_ROUTER] Scan intent: {action} on {target}")

        # Scan চালাও — 90s timeout
        try:
            scan_results = await asyncio.wait_for(
                execute_scan(action, target),
                timeout=90,
            )
        except asyncio.TimeoutError:
            scan_results = {
                "type": "error",
                "target": target,
                "error": "Scan timed out after 90 seconds",
            }

        scan_id = scan_results.get("scan_id")
        scan_data = format_scan_results(scan_results)

        # LLM কে scan results দিয়ে analysis করতে বলো
        llm_prompt = (
            f'User request: "{request.prompt}"\n\n'
            f"Scan results:\n{scan_data}\n\n"
            f"Based on these results, provide a professional security analysis. "
            f"Explain what the findings mean from a security perspective. "
            f"Highlight any risks or concerns. Be specific and technical. "
            f"Do not repeat the raw data — interpret it."
        )

        try:
            llm_result = await asyncio.wait_for(
                asyncio.to_thread(
                    llm_provider.chat,
                    [{"role": "user", "content": llm_prompt}]
                ),
                timeout=180,
            )
            if llm_result.get("success"):
                response_text = f"{scan_data}\n\nAnalysis:\n{llm_result['response']}"
            else:
                response_text = scan_data
        except asyncio.TimeoutError:
            response_text = f"{scan_data}\n\n(AI analysis timed out — scan data above is complete)"

    else:
        # Regular chat — LLM directly answers
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    llm_provider.chat,
                    [{"role": "user", "content": request.prompt}]
                ),
                timeout=180,
            )
            if result.get("success"):
                response_text = result["response"]
            else:
                response_text = f"Error: {result.get('error', 'Unknown error')}"
        except asyncio.TimeoutError:
            response_text = "Response timed out. Please try a shorter question."

    conversations[session_id].append({"role": "assistant", "content": response_text})
    conversation_history[session_id]["messages"] = conversations[session_id]

    return ChatResponse(
        response=response_text,
        session_id=session_id,
        provider="local",
        scan_id=scan_id,
    )


@router.get("/history")
async def get_chat_history():
    try:
        history_list = []
        for session_id, data in conversation_history.items():
            messages = data.get("messages", [])
            preview = "New conversation"
            if messages:
                first_msg = messages[0].get("content", "")
                preview = first_msg[:50] if len(first_msg) > 50 else first_msg
            history_list.append({
                "session_id": session_id,
                "preview": preview,
                "created_at": data.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "message_count": len(messages),
            })
        history_list.sort(key=lambda x: x["created_at"], reverse=True)
        return {"conversations": history_list}
    except Exception as e:
        print(f"[LLM_ROUTER] History error: {e}")
        return {"conversations": []}


@router.get("/history/{session_id}")
async def get_conversation(session_id: str):
    try:
        if session_id not in conversation_history:
            raise HTTPException(status_code=404, detail="Conversation not found")
        return {"messages": conversation_history[session_id].get("messages", [])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))