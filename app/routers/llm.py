from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, AsyncGenerator, Any, Dict
import uuid
import asyncio
import re
import json
from datetime import datetime

from app.llm_provider import llm_provider
from app.llm.system_prompt import SYSTEM_PROMPT

from app.port_scanner.scanner import scan_ports
from app.crawl.crawler import crawl_website
from app.subdomain.discovery import discover_subdomains
from app.tech.detection import detect_technologies
from app.security.ssl import analyze_ssl
from app.security.headers import analyze_headers
from app.firewall.detection import detect_firewall
from app.screenshot.capture import capture_screenshot
from app.js_scanner.scanner import scan_javascript

from app.report.pdf_generator import generate_pdf_report
from app.database.db import get_scan_by_id, save_scan

router = APIRouter(prefix="/api/llm", tags=["llm"])


class ChatRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None
    show_reasoning: bool = True


class ChatResponse(BaseModel):
    response: str
    session_id: str
    provider: Optional[str] = None
    scan_id: Optional[str] = None
    reasoning: Optional[str] = None


conversations = {}
conversation_history = {}


def get_session_context(session_id: str) -> dict:
    if session_id not in conversation_history:
        conversation_history[session_id] = {
            "session_id": session_id,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "messages": [],
            "last_action": None,
            "last_target": None,
            "last_scan_id": None,
            "last_scan_data": None,
            "last_full_result": None,
        }
    return conversation_history[session_id]


def update_session_context(session_id: str, action: str, target: str, scan_data: str, scan_id: str = None, full_result: dict = None):
    ctx = get_session_context(session_id)
    ctx["last_action"] = action
    ctx["last_target"] = target
    ctx["last_scan_data"] = scan_data
    if scan_id:
        ctx["last_scan_id"] = scan_id
    if full_result:
        ctx["last_full_result"] = full_result


def extract_domain(prompt: str) -> Optional[str]:
    url_match = re.search(
        r'https?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,})',
        prompt
    )
    if url_match:
        return url_match.group(1)

    domain_match = re.search(
        r'\b([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b',
        prompt
    )
    if domain_match:
        candidate = domain_match.group(1)
        skip_words = {
            "example.com", "do", "of", "in", "on", "for", "the",
            "this", "that", "can", "you", "me", "my", "is", "it",
        }
        if candidate.lower() not in skip_words:
            return candidate

    return None


def detect_scan_intent(prompt: str, context: dict = None) -> Optional[dict]:
    p = prompt.lower()
    domain = extract_domain(prompt)

    if not domain and context and context.get("last_target"):
        domain = context["last_target"]

    report_keywords = [
        "report", "pdf", "download", "generate report", "export",
        "get report", "create report", "make report", "generate a report"
    ]
    if any(kw in p for kw in report_keywords):
        print(f"[LLM_ROUTER] Report request detected for domain: {domain}")
        return {"action": "generate_report", "target": domain}

    if not domain:
        return None

    module_keywords = {
        "js": ["js", "javascript", "js files", "api key", "js analysis", "javascript analysis"],
        "subdomain": ["subdomain", "sub domains", "dns enum", "subdomain discovery"],
        "crawl": ["crawl", "crawling", "endpoint", "endpoints", "find urls", "discover urls", "find pages"],
        "tech": ["tech", "technology", "technologies", "stack", "built with", "framework", "cms"],
        "ssl": ["ssl", "certificate", "tls", "cert", "https check", "expiry"],
        "headers": ["header", "headers", "security header", "hsts", "csp", "x-frame"],
        "firewall": ["firewall", "waf", "cloudflare check", "waf detect", "ddos protection"],
        "screenshot": ["screenshot", "capture", "visual", "look like", "see the site"],
        "port_scan": ["port", "ports", "port scan", "open ports", "scan ports", "nmap"],
    }

    mentioned_modules = []
    for action, keywords in module_keywords.items():
        if any(keyword in p for keyword in keywords):
            mentioned_modules.append(action)

    if len(mentioned_modules) > 1:
        return {"action": "full_scan", "target": domain}

    for action, keywords in module_keywords.items():
        if any(keyword in p for keyword in keywords):
            return {"action": action, "target": domain}

    if any(w in p for w in ["full scan", "complete scan", "scan everything", "all modules", "full recon"]):
        return {"action": "full_scan", "target": domain}
    elif any(w in p for w in ["scan", "check", "analyze", "analyse", "recon", "reconnaissance", "audit"]):
        return {"action": "full_scan", "target": domain}

    return None


def is_follow_up_request(prompt: str) -> bool:
    p = prompt.lower()
    follow_up_keywords = [
        "list", "show", "give", "output", "result", "results",
        "display", "tell", "what are", "what is", "show me", "give me"
    ]
    return any(keyword in p for keyword in follow_up_keywords)


def safe_result(result: Any) -> Any:
    if isinstance(result, Exception):
        return {"error": str(result)}
    if hasattr(result, 'dict'):
        return result.dict()
    if isinstance(result, dict):
        return result
    if result is None:
        return {"error": "No data returned"}
    return result


async def execute_scan(action: str, domain: str) -> dict:
    try:
        url = f"https://{domain}"

        if action == "full_scan":
            results_list = await asyncio.gather(
                asyncio.to_thread(scan_ports, url, "top50"),
                asyncio.to_thread(crawl_website, url),
                asyncio.to_thread(discover_subdomains, domain),
                asyncio.to_thread(detect_technologies, url),
                asyncio.to_thread(analyze_ssl, url),
                asyncio.to_thread(analyze_headers, url),
                asyncio.to_thread(detect_firewall, url),
                asyncio.to_thread(scan_javascript, url),
                capture_screenshot(url),
                return_exceptions=True,
            )
            return {
                "type": "full_scan",
                "target": domain,
                "url": url,
                "ports": safe_result(results_list[0]),
                "crawl": safe_result(results_list[1]),
                "subdomains": safe_result(results_list[2]),
                "tech": safe_result(results_list[3]),
                "ssl": safe_result(results_list[4]),
                "headers": safe_result(results_list[5]),
                "firewall": safe_result(results_list[6]),
                "js": safe_result(results_list[7]),
                "screenshot": safe_result(results_list[8]),
                "scan_id": str(uuid.uuid4()),
            }

        elif action == "port_scan":
            result = await asyncio.to_thread(scan_ports, url, "top50")
            return {"type": "port_scan", "target": domain, "data": safe_result(result), "url": url}

        elif action == "crawl":
            result = await asyncio.to_thread(crawl_website, url)
            return {"type": "crawl", "target": domain, "data": safe_result(result), "url": url}

        elif action == "subdomain":
            result = await asyncio.to_thread(discover_subdomains, domain)
            return {"type": "subdomain", "target": domain, "data": safe_result(result), "url": url}

        elif action == "tech":
            result = await asyncio.to_thread(detect_technologies, url)
            return {"type": "tech", "target": domain, "data": safe_result(result), "url": url}

        elif action == "ssl":
            result = await asyncio.to_thread(analyze_ssl, url)
            return {"type": "ssl", "target": domain, "data": safe_result(result), "url": url}

        elif action == "headers":
            result = await asyncio.to_thread(analyze_headers, url)
            return {"type": "headers", "target": domain, "data": safe_result(result), "url": url}

        elif action == "firewall":
            result = await asyncio.to_thread(detect_firewall, url)
            return {"type": "firewall", "target": domain, "data": safe_result(result), "url": url}

        elif action == "screenshot":
            result = await capture_screenshot(url)
            return {"type": "screenshot", "target": domain, "data": safe_result(result), "url": url}

        elif action == "js":
            result = await asyncio.to_thread(scan_javascript, url)
            if result is None:
                result = {"error": "JS scanner returned no data"}
            elif isinstance(result, dict) and not result.get("total") and not result.get("error"):
                result["error"] = "No JavaScript files found or scan produced no data"
            return {"type": "js", "target": domain, "data": safe_result(result), "url": url}

        else:
            return {"type": "unknown", "target": domain, "data": None, "url": url}

    except Exception as e:
        return {"type": "error", "target": domain, "data": None, "error": str(e), "url": url}


def format_scan_results(scan_results: dict) -> str:
    if not scan_results:
        return "No results available."

    scan_type = scan_results.get("type")
    target = scan_results.get("target")

    if scan_type == "port_scan":
        data = scan_results.get("data", {})
        if not isinstance(data, dict):
            data = {}
        ports = data.get("open_ports", [])
        if ports:
            lines = [f"  Port {p['port']} | {p.get('service','unknown')} | {p.get('state','open')} | version: {p.get('version','unknown')}" for p in ports[:30]]
            return f"PORT SCAN — {target}\nOpen ports found: {len(ports)}\n" + "\n".join(lines)
        return f"PORT SCAN — {target}\nNo open ports found."

    elif scan_type == "crawl":
        data = scan_results.get("data", {})
        if not isinstance(data, dict):
            data = {}
        endpoints = data.get("endpoints", [])
        if endpoints:
            lines = [f"  {e.get('url','')} | {e.get('method','GET')} | {e.get('status_code','?')} | {e.get('content_type','')}" for e in endpoints[:30]]
            return f"CRAWL — {target}\nEndpoints found: {len(endpoints)}\n" + "\n".join(lines)
        return f"CRAWL — {target}\nNo endpoints found."

    elif scan_type == "subdomain":
        data = scan_results.get("data", {})
        if not isinstance(data, dict):
            data = {}
        subs = data.get("subdomains", [])
        total = data.get("total_found", len(subs))
        if subs:
            display_subs = subs[:20]
            lines = [f"  {s.get('subdomain','')} -> {s.get('ip','unknown')}" for s in display_subs]
            if len(subs) > 20:
                lines.append(f"  ... and {len(subs)-20} more subdomains")
            return f"SUBDOMAIN DISCOVERY — {target}\nTotal subdomains found: {total}\n" + "\n".join(lines)
        return f"SUBDOMAIN DISCOVERY — {target}\nNo subdomains found."

    elif scan_type == "tech":
        data = scan_results.get("data", {})
        if not isinstance(data, dict):
            data = {}
        techs = data.get("technologies", {})
        total = data.get("total_found", 0)
        if techs:
            lines = [f"  {cat}: {', '.join(items)}" for cat, items in techs.items()]
            return f"TECHNOLOGY DETECTION — {target}\nTotal found: {total}\n" + "\n".join(lines)
        return f"TECHNOLOGY DETECTION — {target}\nNo technologies detected."

    elif scan_type == "ssl":
        data = scan_results.get("data", {})
        if not data or not isinstance(data, dict):
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
        if not data or not isinstance(data, dict):
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
        if not data or not isinstance(data, dict):
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
        if data and isinstance(data, dict) and data.get("screenshot_path"):
            return f"SCREENSHOT — {target}\n  Captured and saved at: {data.get('screenshot_path')}"
        err = data.get("error", "Unknown error") if data else "Unknown error"
        return f"SCREENSHOT — {target}\n  Failed: {err}"

    elif scan_type == "js":
        data = scan_results.get("data", {})
        if not data or not isinstance(data, dict):
            return f"JS ANALYSIS — {target}\n  No data available."

        if data.get("error"):
            return f"JS ANALYSIS — {target}\n  Error: {data['error']}"

        total = data.get("total_js_files", data.get("total", 0))
        files = data.get("js_files", data.get("files", []))
        vulnerabilities = data.get("vulnerabilities", [])
        emails = data.get("emails", [])
        api_endpoints = data.get("api_endpoints", [])
        internal_paths = data.get("internal_paths", [])

        lines = [f"JS ANALYSIS — {target}"]
        lines.append(f"  Total JS files found: {total}")

        if files:
            lines.append(f"  Files analyzed: {len(files)}")
            for f in files[:5]:
                url_str = f.get('url', str(f)) if isinstance(f, dict) else str(f)
                lines.append(f"    - {url_str}")
            if len(files) > 5:
                lines.append(f"    ... and {len(files)-5} more")

        if vulnerabilities:
            lines.append(f"  ⚠️ Potential issues found: {len(vulnerabilities)}")
            for v in vulnerabilities[:5]:
                lines.append(f"    - {v.get('file', 'unknown')}: {v.get('pattern', '')}")

        if emails:
            lines.append(f"  📧 Emails found: {', '.join(emails[:5])}")

        if api_endpoints:
            lines.append(f"  🔗 API endpoints: {', '.join(api_endpoints[:5])}")

        if internal_paths:
            lines.append(f"  📁 Internal paths: {', '.join(internal_paths[:5])}")

        if not files and not vulnerabilities and not emails and not api_endpoints and not internal_paths:
            lines.append("  No sensitive data or interesting findings discovered.")

        return "\n".join(lines)

    elif scan_type == "full_scan":
        parts = [f"FULL SCAN — {target}"]
        p = scan_results.get("ports")
        if p and isinstance(p, dict):
            ports = p.get("open_ports", [])
            parts.append(f"  Ports: {len(ports)} open")
        s = scan_results.get("subdomains")
        if s and isinstance(s, dict):
            total = s.get("total_found", 0)
            parts.append(f"  Subdomains: {total} found")
        t = scan_results.get("tech")
        if t and isinstance(t, dict):
            techs = t.get("technologies", {})
            total = sum(len(v) for v in techs.values()) if techs else 0
            parts.append(f"  Technologies: {total} found")
        ssl = scan_results.get("ssl")
        if ssl and isinstance(ssl, dict):
            days = ssl.get("days_remaining", "unknown")
            parts.append(f"  SSL: {days} days remaining")
        h = scan_results.get("headers")
        if h and isinstance(h, dict):
            score = h.get("score", 0)
            parts.append(f"  Security headers score: {score}/100")
        c = scan_results.get("crawl")
        if c and isinstance(c, dict):
            endpoints = c.get("endpoints", [])
            parts.append(f"  Endpoints crawled: {len(endpoints)}")
        fw = scan_results.get("firewall")
        if fw and isinstance(fw, dict):
            if fw.get("detected"):
                parts.append(f"  Firewall: {fw.get('firewall_name', 'Detected')}")
            else:
                parts.append("  Firewall: Not detected")
        js = scan_results.get("js")
        if js and isinstance(js, dict):
            total = js.get("total", 0)
            parts.append(f"  JS files analyzed: {total}")
        return "\n".join(parts)

    elif scan_type == "error":
        return f"SCAN ERROR — {target}\n  {scan_results.get('error', 'Unknown error')}"

    return "Scan completed but no data available."


async def stream_response(messages: list, reasoning_prompt: str = None) -> AsyncGenerator[str, None]:
    try:
        if reasoning_prompt:
            reasoning_result = await llm_provider.chat([
                {"role": "system", "content": "You are a reasoning engine. Provide ONLY the reasoning process. Keep it brief and professional."},
                {"role": "user", "content": reasoning_prompt}
            ])
            if reasoning_result.get("success"):
                reasoning_text = reasoning_result["response"].strip()
                yield f"data: {json.dumps({'type': 'reasoning', 'content': reasoning_text})}\n\n"
                await asyncio.sleep(0.1)
                yield f"data: {json.dumps({'type': 'reasoning_done'})}\n\n"

        result = await llm_provider.chat(messages)
        if result.get("success"):
            response = result["response"].strip()
            if response:
                lines = response.split('\n')
                for line in lines:
                    yield f"data: {json.dumps({'type': 'response', 'content': line + chr(10)})}\n\n"
                    await asyncio.sleep(0.03)
            else:
                yield f"data: {json.dumps({'type': 'error', 'content': 'Empty response from LLM'})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'error', 'content': result.get('error', 'Unknown error')})}\n\n"

        yield f"data: {json.dumps({'type': 'done'})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"


@router.post("/chat/stream")
async def chat_stream(request: ChatRequest):
    print("[LLM_ROUTER] /chat/stream endpoint hit!")
    print("[LLM_ROUTER] Prompt:", request.prompt)

    session_id = request.session_id or str(uuid.uuid4())

    ctx = get_session_context(session_id)
    if session_id not in conversations:
        conversations[session_id] = []

    conversations[session_id].append({"role": "user", "content": request.prompt})

    scan_intent = detect_scan_intent(request.prompt, ctx)
    scan_id = None
    scan_data = None

    if scan_intent:
        action = scan_intent["action"]
        target = scan_intent["target"]
        print(f"[LLM_ROUTER] Scan intent: {action} on {target}")

        # --- PDF Generation (direct response, no LLM) ---
        if action == "generate_report":
            scan_id = ctx.get("last_scan_id")
            full_result = ctx.get("last_full_result")

            if not scan_id or not full_result:
                print("[LLM_ROUTER] No previous scan found, running full scan first...")
                try:
                    full_scan_result = await asyncio.wait_for(
                        execute_scan("full_scan", target),
                        timeout=150
                    )
                    if full_scan_result.get("type") == "error":
                        error_msg = f"❌ Full scan failed: {full_scan_result.get('error')}"
                        async def error_stream():
                            yield f"data: {json.dumps({'type': 'response', 'content': error_msg})}\n\n"
                            yield f"data: {json.dumps({'type': 'done'})}\n\n"
                        return StreamingResponse(error_stream(), media_type="text/event-stream")
                    else:
                        url = full_scan_result.get("url")
                        result_data = {k: v for k, v in full_scan_result.items() if k not in ["type", "target", "scan_id", "url"]}
                        scan_id = await save_scan(url, result_data)
                        full_result = result_data
                        update_session_context(session_id, "full_scan", target, format_scan_results(full_scan_result), scan_id, full_result)
                except asyncio.TimeoutError:
                    error_msg = "⏱️ Full scan timed out. Please try again."
                    async def error_stream():
                        yield f"data: {json.dumps({'type': 'response', 'content': error_msg})}\n\n"
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return StreamingResponse(error_stream(), media_type="text/event-stream")
                except Exception as e:
                    error_msg = f"❌ Error running full scan: {str(e)}"
                    async def error_stream():
                        yield f"data: {json.dumps({'type': 'response', 'content': error_msg})}\n\n"
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return StreamingResponse(error_stream(), media_type="text/event-stream")

            if scan_id and full_result:
                try:
                    url = full_result.get("url", target if target else "unknown")
                    pdf_path = await asyncio.to_thread(generate_pdf_report, full_result, url)
                    download_url = f"/{pdf_path}"
                    link_html = f'<b>📄 Download Report:</b> <a href="{download_url}" target="_blank" style="color: #00ff00; text-decoration: underline; font-weight: bold;">Download PDF</a>'
                    response_text = f"✅ PDF report generated successfully!\n\n{link_html}"
                    update_session_context(session_id, "generate_report", target, response_text, scan_id)

                    async def pdf_stream():
                        for line in response_text.split('\n'):
                            yield f"data: {json.dumps({'type': 'response', 'content': line + chr(10)})}\n\n"
                            await asyncio.sleep(0.05)
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return StreamingResponse(pdf_stream(), media_type="text/event-stream")

                except Exception as e:
                    error_msg = f"❌ Failed to generate PDF: {str(e)}"
                    async def error_stream():
                        yield f"data: {json.dumps({'type': 'response', 'content': error_msg})}\n\n"
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return StreamingResponse(error_stream(), media_type="text/event-stream")
            else:
                error_msg = "❌ No scan data available to generate report. Please run a scan first."
                async def error_stream():
                    yield f"data: {json.dumps({'type': 'response', 'content': error_msg})}\n\n"
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                return StreamingResponse(error_stream(), media_type="text/event-stream")

        # --- Other scan actions ---
        if action in ["subdomain", "full_scan"]:
            scan_timeout = 150
        else:
            scan_timeout = 90

        try:
            scan_results = await asyncio.wait_for(
                execute_scan(action, target),
                timeout=scan_timeout,
            )
        except asyncio.TimeoutError:
            scan_results = {
                "type": "error",
                "target": target,
                "error": f"Scan timed out after {scan_timeout} seconds",
            }

        scan_id = scan_results.get("scan_id")
        scan_data = format_scan_results(scan_results)
        full_result = {k: v for k, v in scan_results.items() if k not in ["type", "target", "scan_id"]}
        update_session_context(session_id, action, target, scan_data, scan_id, full_result)

    else:
        if is_follow_up_request(request.prompt) and ctx.get("last_scan_data"):
            action = ctx["last_action"]
            target = ctx["last_target"]
            scan_data = ctx["last_scan_data"]
            scan_id = ctx.get("last_scan_id")
            print(f"[LLM_ROUTER] Follow-up detected, using previous {action} result for {target}")
        else:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": request.prompt}
            ]
            reasoning_prompt = None
            if request.show_reasoning:
                reasoning_prompt = f"User asked: '{request.prompt}'. Explain your reasoning for your response."

            return StreamingResponse(
                stream_response(messages, reasoning_prompt),
                media_type="text/event-stream"
            )

    # --- Build prompt that answers the user's original question ---
    user_question = request.prompt
    if action == "port_scan":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a port scan on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about open ports, services, or security risks, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "crawl":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a crawl on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about endpoints, hidden directories, or interesting URLs, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "subdomain":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a subdomain scan on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about subdomains, their IPs, or potential attack surfaces, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "js":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a JavaScript analysis on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about frameworks, API keys, emails, or internal paths, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "ssl":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed an SSL analysis on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about certificate validity, expiry, or issuer, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "headers":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a security headers analysis on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about missing headers or security score, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "firewall":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a firewall/WAF detection on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about WAF presence or protection level, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "tech":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a technology detection on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about frameworks, CMS, CDN, or tech stack, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )
    elif action == "screenshot":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I attempted to capture a screenshot of {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about the visual appearance or layout, describe what you see from the screenshot. "
            f"Be concise but thorough."
        )
    else:  # full_scan
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a full scan on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"If the user asked about the overall security posture, technology stack, or interesting findings, extract that information and explain it clearly. "
            f"Be concise but thorough."
        )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": llm_prompt}
    ]

    reasoning_prompt = None
    if request.show_reasoning:
        reasoning_prompt = f"User asked: '{request.prompt}'. I performed a {action} scan on {target}. Explain your reasoning for the analysis you're about to provide."

    return StreamingResponse(
        stream_response(messages, reasoning_prompt),
        media_type="text/event-stream"
    )


@router.post("/chat")
async def chat(request: ChatRequest):
    """Non-streaming chat endpoint with PDF support and direct answer"""
    print("[LLM_ROUTER] /chat endpoint hit!")
    print("[LLM_ROUTER] Prompt:", request.prompt)

    session_id = request.session_id or str(uuid.uuid4())

    ctx = get_session_context(session_id)
    if session_id not in conversations:
        conversations[session_id] = []

    conversations[session_id].append({"role": "user", "content": request.prompt})

    scan_intent = detect_scan_intent(request.prompt, ctx)
    response_text = ""
    scan_id = None
    reasoning_text = ""
    scan_data = None

    if scan_intent:
        action = scan_intent["action"]
        target = scan_intent["target"]
        print(f"[LLM_ROUTER] Scan intent: {action} on {target}")

        if action == "generate_report":
            scan_id = ctx.get("last_scan_id")
            full_result = ctx.get("last_full_result")

            if not scan_id or not full_result:
                print("[LLM_ROUTER] No previous scan found, running full scan first...")
                try:
                    full_scan_result = await asyncio.wait_for(
                        execute_scan("full_scan", target),
                        timeout=150
                    )
                    if full_scan_result.get("type") == "error":
                        response_text = f"❌ Full scan failed: {full_scan_result.get('error')}"
                    else:
                        url = full_scan_result.get("url")
                        result_data = {k: v for k, v in full_scan_result.items() if k not in ["type", "target", "scan_id", "url"]}
                        scan_id = await save_scan(url, result_data)
                        full_result = result_data
                        update_session_context(session_id, "full_scan", target, format_scan_results(full_scan_result), scan_id, full_result)
                except asyncio.TimeoutError:
                    response_text = "⏱️ Full scan timed out. Please try again."
                except Exception as e:
                    response_text = f"❌ Error running full scan: {str(e)}"

            if scan_id and full_result:
                try:
                    url = full_result.get("url", target if target else "unknown")
                    pdf_path = await asyncio.to_thread(generate_pdf_report, full_result, url)
                    download_url = f"/{pdf_path}"
                    link_html = f'<b>📄 Download Report:</b> <a href="{download_url}" target="_blank" style="color: #00ff00; text-decoration: underline; font-weight: bold;">Download PDF</a>'
                    response_text = f"✅ PDF report generated successfully!\n\n{link_html}"
                    update_session_context(session_id, "generate_report", target, response_text, scan_id)
                except Exception as e:
                    response_text = f"❌ Failed to generate PDF: {str(e)}"
            elif not response_text:
                response_text = "❌ No scan data available to generate report. Please run a scan first."

            conversations[session_id].append({"role": "assistant", "content": response_text})
            return ChatResponse(
                response=response_text,
                session_id=session_id,
                provider="local",
                scan_id=scan_id,
                reasoning=None,
            )

        if action in ["subdomain", "full_scan"]:
            scan_timeout = 150
        else:
            scan_timeout = 90

        try:
            scan_results = await asyncio.wait_for(
                execute_scan(action, target),
                timeout=scan_timeout,
            )
        except asyncio.TimeoutError:
            scan_results = {
                "type": "error",
                "target": target,
                "error": f"Scan timed out after {scan_timeout} seconds",
            }

        scan_id = scan_results.get("scan_id")
        scan_data = format_scan_results(scan_results)
        full_result = {k: v for k, v in scan_results.items() if k not in ["type", "target", "scan_id"]}
        update_session_context(session_id, action, target, scan_data, scan_id, full_result)

    else:
        if is_follow_up_request(request.prompt) and ctx.get("last_scan_data"):
            action = ctx["last_action"]
            target = ctx["last_target"]
            scan_data = ctx["last_scan_data"]
            scan_id = ctx.get("last_scan_id")
            print(f"[LLM_ROUTER] Follow-up (non-stream) using previous {action} result for {target}")
        else:
            try:
                messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": request.prompt}
                ]

                if request.show_reasoning:
                    reasoning_result = await llm_provider.chat([
                        {"role": "system", "content": "You are a reasoning engine. Provide a brief step-by-step reasoning about how you will answer the user's question. Keep it concise and professional."},
                        {"role": "user", "content": f"User asked: '{request.prompt}'. Explain your reasoning for your response."}
                    ])
                    if reasoning_result.get("success"):
                        reasoning_text = reasoning_result["response"]

                result = await asyncio.wait_for(
                    llm_provider.chat(messages),
                    timeout=240,
                )
                if result.get("success"):
                    response_text = result["response"]
                else:
                    response_text = f"Error: {result.get('error', 'Unknown error')}"
            except asyncio.TimeoutError:
                response_text = "Response timed out. Please try a shorter question."

            conversations[session_id].append({"role": "assistant", "content": response_text})
            return ChatResponse(
                response=response_text,
                session_id=session_id,
                provider="local",
                scan_id=None,
                reasoning=reasoning_text if request.show_reasoning else None,
            )

    # Build prompt that answers the user's original question (same as streaming)
    user_question = request.prompt
    if action == "port_scan":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a port scan on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "crawl":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a crawl on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "subdomain":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a subdomain scan on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "js":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a JavaScript analysis on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "ssl":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed an SSL analysis on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "headers":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a security headers analysis on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "firewall":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a firewall/WAF detection on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "tech":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a technology detection on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    elif action == "screenshot":
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I attempted to capture a screenshot of {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )
    else:
        llm_prompt = (
            f"The user asked: \"{user_question}\"\n\n"
            f"I performed a full scan on {target} and got these results:\n\n"
            f"{scan_data}\n\n"
            f"Based on these results, please answer the user's question directly and specifically. "
            f"Do not just repeat the scan results. Provide analysis, insights, and conclusions that address the user's query. "
            f"Be concise but thorough."
        )

    try:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": llm_prompt}
        ]

        if request.show_reasoning:
            reasoning_result = await llm_provider.chat([
                {"role": "system", "content": "You are a reasoning engine. Provide a brief step-by-step reasoning about how you will answer the user's question. Keep it concise and professional."},
                {"role": "user", "content": f"User asked: '{request.prompt}'. I performed a {action} scan on {target}. Explain your reasoning for the analysis you're about to provide."}
            ])
            if reasoning_result.get("success"):
                reasoning_text = reasoning_result["response"]

        llm_result = await asyncio.wait_for(
            llm_provider.chat(messages),
            timeout=240,
        )
        if llm_result.get("success"):
            response_text = llm_result["response"]
        else:
            response_text = scan_data
    except asyncio.TimeoutError:
        response_text = f"{scan_data}\n\n(AI analysis timed out — scan data above is complete)"

    conversations[session_id].append({"role": "assistant", "content": response_text})

    return ChatResponse(
        response=response_text,
        session_id=session_id,
        provider="local",
        scan_id=scan_id,
        reasoning=reasoning_text if request.show_reasoning else None,
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