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

# --- NEW IMPORTS ---
from app.osint.collector import OSINTCollector
from app.prioritization.risk_score import calculate_risk
from app.threat_intel import ThreatIntelCollector

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

    js_keywords = [
        "js", "javascript", "java script", "js files", "javascript files",
        "scan js", "js analysis", "javascript analysis",
        "find js", "javascript scanner"
    ]
    if any(kw in p for kw in js_keywords):
        print(f"[LLM_ROUTER] JS request detected for domain: {domain}")
        return {"action": "js", "target": domain}

    module_keywords = {
        "subdomain": ["subdomain", "sub domains", "dns enum", "subdomain discovery"],
        "crawl": ["crawl", "crawling", "endpoint", "endpoints", "find urls", "discover urls", "find pages"],
        "tech": ["tech", "technology", "technologies", "stack", "built with", "framework", "cms"],
        "ssl": ["ssl", "certificate", "tls", "cert", "https check", "expiry"],
        "headers": ["header", "headers", "security header", "hsts", "csp", "x-frame"],
        "firewall": ["firewall", "waf", "cloudflare check", "waf detect", "ddos protection"],
        "screenshot": ["screenshot", "capture", "visual", "look like", "see the site"],
        "port_scan": ["port", "ports", "port scan", "open ports", "scan ports", "nmap"],
        "osint": ["osint", "whois", "wayback", "crt.sh", "dns records"],
        "risk": ["risk", "ctem", "prioritization", "risk score", "risk assessment"],
        "threat_intel": ["threat", "threat intel", "threat intelligence", "reputation", "malicious", "virustotal", "abuseipdb"],
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

def is_question(prompt: str) -> bool:
    question_words = ["what", "which", "how", "is", "are", "who", "when", "why", "where", "does", "do", "can", "will"]
    prompt_lower = prompt.lower()
    return "?" in prompt or any(word in prompt_lower.split() for word in question_words)

def is_list_request(prompt: str) -> bool:
    list_keywords = ["list", "show", "output", "display", "give me", "show me"]
    prompt_lower = prompt.lower()
    return any(kw in prompt_lower for kw in list_keywords)

def clean_reasoning_from_response(text: str) -> str:
    lines = text.split('\n')
    cleaned = []
    reasoning_patterns = [
        r'^step\s*\d+', r'^reasoning', r'^thinking',
        r'^i will', r'^let me', r'^based on', r'^according to',
        r'^my analysis', r'^the user asked', r'^i performed',
        r'^here is', r'^output the following', r'^your entire response',
        r'^do not add', r'^if the data', r'^be helpful',
        r'^to answer', r'^first,', r'^second,', r'^next,',
        r'^finally,', r'^in summary', r'^overview',
        r'^thinking process', r'^reasoning process', r'^chain of thought',
        r'^i will now', r'^let me think', r'^my thought process',
        r'^internal analysis', r'^step by step', r'^here are',
        r'^i can see', r'^i notice', r'^the data shows',
        r'^from the scan', r'^the results indicate',
        r'^i have analyzed', r'^i will provide',
        r'^as you can see', r'^it seems that',
        r'^the scan reveals', r'^this suggests',
        r'^in the data', r'^based on the data',
        r'^i found', r'^i discovered', r'^i identified',
        r'^going through', r'^looking at',
        r'^my recommendation', r'^i suggest',
        r'^the following', r'^below are',
        r'^checking the', r'^examining the',
        r'^i will list', r'^i will show',
        r'^let\'s', r'^lets', r'^we can',
        r'^you can see', r'^please note',
        r'^i should mention', r'^i think',
        r'^i believe', r'^in my opinion',
        r'^refined', r'^wait', r'^actually', r'^looking at',
        r'^re-evaluating', r'^strategy', r'^check constraints',
        r'^if i', r'^however', r'^since the user',
        r'^the input', r'^the provided', r'^the data provided',
        r'^\*', r'^refining strategy', r'^wait,', r'^actually,',
        r'^let\'s look', r'^since i don\'t have', r'^i should',
        r'^i will', r'^if i follow', r'^the user is', r'^contextual data',
        r'^refined strategy', r'^considering that', r'^given that',
        r'^note that', r'^the prompt also says', r'^the instruction says',
        r'^i have', r'^since the user', r'^to answer', r'^i\'ll', r'^i\'m',
        r'^i am', r'^what i', r'^the best', r'^one way', r'^another way',
        r'^instead', r'^rather than', r'^however,', r'^therefore,',
        r'^thus,', r'^so,', r'^in that case', r'^the key', r'^my goal',
        r'^ultimately', r'^in essence', r'^to summarize', r'^in short',
        r'^all in all', r'^looking at the', r'^based on the',
        r'^the scan shows', r'^i see', r'^i notice that',
        r'^the user wants', r'^the raw data', r'^wait, looking',
        r'^port scan:', r'^subdomains:', r'^tech:', r'^ssl:',
        r'^security headers:', r'^firewall:', r'^found \d+',
        r'^\- \(the specific', r'^since the specific',
        r'^i might have to', r'^but usually,',
        r'^this is a summary', r'^if i don\'t have',
        r'^i can\'t fill', r'^i will represent',
        r'^port scan section', r'^subdomain section',
        r'^technology section', r'^ssl section',
        r'^security headers section', r'^firewall section',
        r'^found \d+ open ports', r'^subdomains:', r'^techs:',
        r'^ssl:', r'^security score:', r'^endpoints:',
        r'^firewall:', r'^refining approach', r'^correction:',
        r'^let\'s check', r'^if the data is missing',
        r'^i should still', r'^wait\s*\*', r'^\s*\*wait',
        r'^refining the content', r'^actually, if i have',
        r'^since i don\'t know', r'^i don\'t have',
    ]
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        skip = False
        for pattern in reasoning_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                skip = True
                break
        if not skip:
            cleaned.append(line)
    if not cleaned:
        return text
    return '\n'.join(cleaned)

def extract_answer_from_llm_response(raw: str) -> str:
    if "### ANSWER" in raw:
        parts = raw.split("### ANSWER")
        if len(parts) > 1:
            answer_part = parts[1].strip()
            cleaned = clean_reasoning_from_response(answer_part)
            if cleaned:
                return cleaned
            return answer_part
    return clean_reasoning_from_response(raw)

def extract_reasoning_from_llm_response(raw: str) -> str:
    if "### REASONING" in raw and "### ANSWER" in raw:
        start = raw.find("### REASONING") + len("### REASONING")
        end = raw.find("### ANSWER")
        return raw[start:end].strip()
    return ""

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
            osint_collector = OSINTCollector(domain)
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
                osint_collector.run_all(),
                asyncio.to_thread(calculate_risk, {}),
                return_exceptions=True,
            )
            ports_res, crawl_res, subdomain_res, tech_res, ssl_res, headers_res, firewall_res, js_res, screenshot_res, osint_res, risk_res = results_list

            full_result = {
                "type": "full_scan",
                "target": domain,
                "url": url,
                "ports": safe_result(ports_res),
                "crawl": safe_result(crawl_res),
                "subdomains": safe_result(subdomain_res),
                "tech": safe_result(tech_res),
                "ssl": safe_result(ssl_res),
                "headers": safe_result(headers_res),
                "firewall": safe_result(firewall_res),
                "js": safe_result(js_res),
                "screenshot": safe_result(screenshot_res),
                "osint": safe_result(osint_res),
                "scan_id": str(uuid.uuid4()),
            }

            risk_data = {
                "ssl": full_result.get("ssl"),
                "security_headers": full_result.get("headers"),
                "ports": full_result.get("ports"),
                "firewall": full_result.get("firewall"),
                "subdomains": full_result.get("subdomains"),
                "osint": full_result.get("osint"),
                "crawl": full_result.get("crawl"),
                "js_scanner": full_result.get("js"),
            }
            try:
                risk_calc = await asyncio.to_thread(calculate_risk, risk_data)
                full_result["risk"] = safe_result(risk_calc)
            except Exception as e:
                full_result["risk"] = {"error": str(e)}

            # Threat Intelligence
            try:
                subs = full_result.get("subdomains", {})
                ips = []
                if isinstance(subs, dict):
                    for s in subs.get("subdomains", []):
                        if isinstance(s, dict):
                            ip = s.get("ip")
                            if ip and ip != "N/A":
                                ips.append(ip)
                import socket
                try:
                    main_ip = socket.gethostbyname(domain)
                    ips.append(main_ip)
                except:
                    pass
                sub_names = []
                if isinstance(subs, dict):
                    for s in subs.get("subdomains", []):
                        if isinstance(s, dict):
                            name = s.get("subdomain")
                            if name:
                                sub_names.append(name)
                threat_collector = ThreatIntelCollector(domain, ips, sub_names)
                threat_result = await threat_collector.run()
                full_result["threat_intel"] = safe_result(threat_result)
            except Exception as e:
                full_result["threat_intel"] = {"error": str(e)}

            return full_result

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
            elif isinstance(result, dict) and not result.get("total_js_files") and not result.get("error"):
                result["error"] = "No JavaScript files found or scan produced no data"
            return {"type": "js", "target": domain, "data": safe_result(result), "url": url}

        elif action == "osint":
            collector = OSINTCollector(domain)
            result = await collector.run_all()
            return {"type": "osint", "target": domain, "data": safe_result(result), "url": url}

        elif action == "risk":
            scan_result = await execute_scan("full_scan", domain)
            risk = scan_result.get("risk")
            return {"type": "risk", "target": domain, "data": safe_result(risk), "url": url}

        elif action == "threat_intel":
            # For threat intel, we need IPs and subdomains first
            sub_result = await execute_scan("subdomain", domain)
            subs = sub_result.get("data", {})
            ips = []
            if isinstance(subs, dict):
                for s in subs.get("subdomains", []):
                    if isinstance(s, dict):
                        ip = s.get("ip")
                        if ip and ip != "N/A":
                            ips.append(ip)
            import socket
            try:
                main_ip = socket.gethostbyname(domain)
                ips.append(main_ip)
            except:
                pass
            sub_names = []
            if isinstance(subs, dict):
                for s in subs.get("subdomains", []):
                    if isinstance(s, dict):
                        name = s.get("subdomain")
                        if name:
                            sub_names.append(name)
            threat_collector = ThreatIntelCollector(domain, ips, sub_names)
            result = await threat_collector.run()
            return {"type": "threat_intel", "target": domain, "data": safe_result(result), "url": url}

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
        if subs:
            lines = []
            for s in subs:
                sub = s.get('subdomain', '')
                ip = s.get('ip', 'N/A')
                status = s.get('http_status', 'N/A')
                tech = ', '.join(s.get('technologies', [])) if s.get('technologies') else 'N/A'
                ports = ', '.join(map(str, s.get('open_ports', []))) if s.get('open_ports') else 'N/A'
                sensitive = '⚠️' if s.get('sensitive') else ''
                lines.append(f"  {sub} {sensitive} -> IP: {ip} | HTTP: {status} | Tech: {tech} | Open Ports: {ports}")
            return f"SUBDOMAIN DISCOVERY — {target}\nTotal subdomains found: {len(subs)}\n" + "\n".join(lines)
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
            fw_name = data.get('firewall_name', 'Unknown')
            cdn = data.get('cdn_detected', False)
            label = "CDN" if cdn else "WAF"
            return (
                f"FIREWALL DETECTION — {target}\n"
                f"  Detected: YES\n"
                f"  {label}: {fw_name}\n"
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
        tokens = data.get("tokens", [])
        source_maps = data.get("source_maps", [])

        lines = [f"JS ANALYSIS — {target}"]
        lines.append(f"  Total JS files found: {total}")

        if files:
            lines.append(f"  Files analyzed: {len(files)}")
            for f in files[:5]:
                url_str = f.get('url', str(f)) if isinstance(f, dict) else str(f)
                lines.append(f"    - {url_str}")
            if len(files) > 5:
                lines.append(f"    ... and {len(files)-5} more")

        if tokens:
            lines.append(f"  ⚠️ Potential secrets/tokens found: {len(tokens)}")
            lines.append(f"    Examples: {', '.join(tokens[:3])}")

        if source_maps:
            lines.append(f"  📁 Source maps exposed: {len(source_maps)}")

        if vulnerabilities:
            lines.append(f"  ⚠️ Potential issues: {len(vulnerabilities)}")
            for v in vulnerabilities[:5]:
                lines.append(f"    - {v.get('file', 'unknown')}: {v.get('pattern', '')}")

        if emails:
            lines.append(f"  📧 Emails found: {', '.join(emails[:5])}")

        if api_endpoints:
            lines.append(f"  🔗 API endpoints: {', '.join(api_endpoints[:5])}")

        if internal_paths:
            lines.append(f"  📁 Internal paths: {', '.join(internal_paths[:5])}")

        if not files and not vulnerabilities and not emails and not api_endpoints and not internal_paths and not tokens:
            lines.append("  No sensitive data or interesting findings discovered.")

        return "\n".join(lines)

    elif scan_type == "osint":
        data = scan_results.get("data", {})
        if not data or not isinstance(data, dict):
            return f"OSINT — {target}\n  No data available."
        lines = [f"OSINT — {target}"]
        whois = data.get("whois", {})
        if whois and not whois.get("error"):
            lines.append(f"  WHOIS: Registrar {whois.get('registrar', 'N/A')}, Created {whois.get('creation_date', 'N/A')}, Expires {whois.get('expiration_date', 'N/A')}")
            ns = whois.get('name_servers', [])
            if ns:
                lines.append(f"  Name Servers: {', '.join(ns)}")
        dns = data.get("dns_records", {})
        if dns:
            lines.append("  DNS Records:")
            for qtype, values in dns.items():
                if values:
                    lines.append(f"    {qtype}: {', '.join(values)}")
        wayback = data.get("wayback_urls", [])
        if wayback:
            lines.append(f"  Wayback URLs: {len(wayback)} found (first 5):")
            for w in wayback[:5]:
                lines.append(f"    - {w}")
        crt = data.get("crt_subdomains", [])
        if crt:
            lines.append(f"  crt.sh subdomains: {len(crt)} found (first 5):")
            for c in crt[:5]:
                lines.append(f"    - {c}")
        if not any([whois, dns, wayback, crt]):
            lines.append("  No OSINT data found.")
        return "\n".join(lines)

    elif scan_type == "risk":
        data = scan_results.get("data", {})
        if not data or not isinstance(data, dict):
            return f"RISK — {target}\n  No risk data available."
        if data.get("error"):
            return f"RISK — {target}\n  Error: {data['error']}"
        lines = [f"RISK ASSESSMENT — {target}"]
        lines.append(f"  Overall Risk: {data.get('overall_risk', 'UNKNOWN')}")
        lines.append(f"  Score: {data.get('score', 'N/A')}/100")
        lines.append(f"  Headline: {data.get('headline', '')}")
        summary = data.get("summary", {})
        if summary:
            lines.append(f"  Severity Summary: Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)}")
        findings = data.get("findings", [])
        if findings:
            lines.append(f"  Findings ({len(findings)}):")
            for f in findings[:5]:
                lines.append(f"    - [{f.get('severity')}] {f.get('description')}")
            if len(findings) > 5:
                lines.append(f"    ... and {len(findings)-5} more")
        observations = data.get("observations", [])
        if observations:
            lines.append(f"  Observations ({len(observations)}):")
            for obs in observations[:3]:
                lines.append(f"    - {obs.get('description')}")
        return "\n".join(lines)

    elif scan_type == "threat_intel":
        data = scan_results.get("data", {})
        if not data or not isinstance(data, dict):
            return f"THREAT INTEL — {target}\n  No data available."
        if data.get("error"):
            return f"THREAT INTEL — {target}\n  Error: {data['error']}"
        lines = [f"THREAT INTELLIGENCE — {data.get('domain', target)}"]
        summary = data.get("summary", {})
        lines.append(f"  Entities checked: {summary.get('total_entities', 0)}")
        lines.append(f"  Malicious entities found: {summary.get('malicious_count', 0)}")
        lines.append(f"  High-risk entities: {summary.get('high_risk_count', 0)}")

        malicious = data.get("malicious_entities", [])
        if malicious:
            lines.append(f"  ⚠️ Malicious entities: {', '.join(malicious[:5])}")
        high_risk = data.get("high_risk_entities", [])
        if high_risk:
            lines.append(f"  ⚠️ High-risk entities: {', '.join(high_risk[:5])}")

        details = data.get("details", {})
        scored_items = []
        for entity, entity_data in details.items():
            if isinstance(entity_data, dict) and "risk_score" in entity_data:
                scored_items.append((entity, entity_data["risk_score"]))
        scored_items.sort(key=lambda x: x[1], reverse=True)
        if scored_items:
            lines.append("  Top risk scores:")
            for entity, score in scored_items[:3]:
                lines.append(f"    - {entity}: {score}/100")

        return "\n".join(lines)

    elif scan_type == "full_scan":
        parts = [f"FULL SCAN — {target}"]

        p = scan_results.get("ports")
        if p and isinstance(p, dict):
            ports = p.get("open_ports", [])
            if ports:
                parts.append(f"\nPORT SCAN:\nFound {len(ports)} open ports:")
                for port in ports[:30]:
                    parts.append(f"  - Port {port.get('port', '?')} | {port.get('service', 'unknown')} | {port.get('state', 'open')} | version: {port.get('version', 'unknown')}")
                if len(ports) > 30:
                    parts.append(f"  ... and {len(ports)-30} more ports")
            else:
                parts.append("\nPORT SCAN:\nNo open ports found.")

        s = scan_results.get("subdomains")
        if s and isinstance(s, dict):
            subs = s.get("subdomains", [])
            if subs:
                parts.append(f"\nSUBDOMAIN DISCOVERY:\nFound {len(subs)} subdomains:")
                for sub in subs[:20]:
                    sub_name = sub.get('subdomain', 'unknown')
                    ip = sub.get('ip', 'N/A')
                    status = sub.get('http_status', 'N/A')
                    tech = ', '.join(sub.get('technologies', [])) if sub.get('technologies') else 'N/A'
                    ports = ', '.join(map(str, sub.get('open_ports', []))) if sub.get('open_ports') else 'N/A'
                    sensitive = ' (⚠️ sensitive)' if sub.get('sensitive') else ''
                    parts.append(f"  - {sub_name}{sensitive} -> IP: {ip} | HTTP: {status} | Tech: {tech} | Ports: {ports}")
                if len(subs) > 20:
                    parts.append(f"  ... and {len(subs)-20} more subdomains")
            else:
                parts.append("\nSUBDOMAIN DISCOVERY:\nNo subdomains found.")

        t = scan_results.get("tech")
        if t and isinstance(t, dict):
            techs = t.get("technologies", {})
            if techs:
                parts.append("\nTECHNOLOGY DETECTION:")
                for cat, items in techs.items():
                    parts.append(f"  {cat}: {', '.join(items)}")
            else:
                parts.append("\nTECHNOLOGY DETECTION:\nNo technologies detected.")

        ssl = scan_results.get("ssl")
        if ssl and isinstance(ssl, dict):
            parts.append(f"\nSSL ANALYSIS:")
            parts.append(f"  - Issued To: {ssl.get('issued_to', 'unknown')}")
            parts.append(f"  - Issued By: {ssl.get('issued_by', 'unknown')}")
            parts.append(f"  - Valid From: {ssl.get('valid_from', 'unknown')}")
            parts.append(f"  - Valid Until: {ssl.get('valid_until', 'unknown')}")
            parts.append(f"  - Days Remaining: {ssl.get('days_remaining', 'unknown')}")
            parts.append(f"  - Expired: {'YES' if ssl.get('is_expired') else 'NO'}")

        h = scan_results.get("headers")
        if h and isinstance(h, dict):
            present = h.get("present", {})
            missing = h.get("missing", [])
            score = h.get("score", 0)
            parts.append(f"\nSECURITY HEADERS — Score: {score}/100")
            if present:
                parts.append("  Present (✓):")
                for header, value in present.items():
                    parts.append(f"    - {header}: {value[:80]}")
            if missing:
                parts.append("  Missing (✗):")
                for header in missing:
                    parts.append(f"    - {header}")

        c = scan_results.get("crawl")
        if c and isinstance(c, dict):
            endpoints = c.get("endpoints", [])
            if endpoints:
                parts.append(f"\nCRAWL:\nFound {len(endpoints)} endpoints:")
                for ep in endpoints[:30]:
                    parts.append(f"  - {ep.get('url', 'unknown')} | {ep.get('method', 'GET')} | {ep.get('status_code', '?')} | {ep.get('content_type', '')}")
                if len(endpoints) > 30:
                    parts.append(f"  ... and {len(endpoints)-30} more endpoints")
            else:
                parts.append("\nCRAWL:\nNo endpoints found.")

        fw = scan_results.get("firewall")
        if fw and isinstance(fw, dict):
            parts.append(f"\nFIREWALL DETECTION:")
            if fw.get('detected'):
                fw_name = fw.get('firewall_name', 'Unknown')
                cdn = fw.get('cdn_detected', False)
                label = "CDN" if cdn else "WAF"
                parts.append(f"  - {label}: {fw_name}")
                parts.append(f"  - Evidence: {fw.get('evidence', 'unknown')}")
            else:
                parts.append(f"  - No CDN/WAF detected")

        js = scan_results.get("js")
        if js and isinstance(js, dict):
            total_js = js.get("total_js_files", js.get("total", 0))
            js_files = js.get("js_files", js.get("files", []))
            emails = js.get("emails", [])
            api_endpoints = js.get("api_endpoints", [])
            internal_paths = js.get("internal_paths", [])
            vulnerabilities = js.get("vulnerabilities", [])
            tokens = js.get("tokens", [])
            source_maps = js.get("source_maps", [])

            parts.append(f"\nJAVASCRIPT ANALYSIS:")
            parts.append(f"  - Total JS files found: {total_js}")
            if js_files:
                parts.append(f"  - JS Files (first 5):")
                for f in js_files[:5]:
                    url_str = f.get('url', str(f)) if isinstance(f, dict) else str(f)
                    parts.append(f"    - {url_str}")
                if len(js_files) > 5:
                    parts.append(f"    ... and {len(js_files)-5} more")
            if tokens:
                parts.append(f"  - Potential secrets: {len(tokens)} found")
            if source_maps:
                parts.append(f"  - Source maps exposed: {len(source_maps)}")
            if emails:
                parts.append(f"  - Emails found: {', '.join(emails[:5])}")
            if api_endpoints:
                parts.append(f"  - API endpoints: {', '.join(api_endpoints[:5])}")
            if internal_paths:
                parts.append(f"  - Internal paths: {', '.join(internal_paths[:5])}")
            if vulnerabilities:
                parts.append(f"  - Potential issues: {len(vulnerabilities)} found")

        osint = scan_results.get("osint")
        if osint and isinstance(osint, dict):
            parts.append(f"\nOSINT INTELLIGENCE:")
            whois = osint.get("whois", {})
            if whois and not whois.get("error"):
                parts.append(f"  - WHOIS: Registrar {whois.get('registrar', 'N/A')}, Created {whois.get('creation_date', 'N/A')}")
            wayback = osint.get("wayback_urls", [])
            if wayback:
                parts.append(f"  - Wayback URLs: {len(wayback)} found")
            crt = osint.get("crt_subdomains", [])
            if crt:
                parts.append(f"  - crt.sh subdomains: {len(crt)} found")
            if not any([whois, wayback, crt]):
                parts.append("  - No OSINT data retrieved.")

        risk = scan_results.get("risk")
        if risk and isinstance(risk, dict):
            parts.append(f"\nRISK PRIORITIZATION:")
            parts.append(f"  - Overall Risk: {risk.get('overall_risk', 'UNKNOWN')}")
            parts.append(f"  - Score: {risk.get('score', 'N/A')}/100")
            summary = risk.get("summary", {})
            if summary:
                parts.append(f"  - Severity Counts: Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)}")
            findings = risk.get("findings", [])
            if findings:
                parts.append(f"  - Findings ({len(findings)}):")
                for f in findings[:3]:
                    parts.append(f"    - [{f.get('severity')}] {f.get('description')}")

        threat = scan_results.get("threat_intel")
        if threat and isinstance(threat, dict):
            parts.append(f"\nTHREAT INTELLIGENCE:")
            summary = threat.get("summary", {})
            parts.append(f"  - Entities checked: {summary.get('total_entities', 0)}")
            parts.append(f"  - Malicious entities: {summary.get('malicious_count', 0)}")
            parts.append(f"  - High-risk entities: {summary.get('high_risk_count', 0)}")
            malicious = threat.get("malicious_entities", [])
            if malicious:
                parts.append(f"  - Malicious: {', '.join(malicious[:5])}")

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
            raw_response = result["response"].strip()

            reasoning_part = extract_reasoning_from_llm_response(raw_response)
            answer_part = extract_answer_from_llm_response(raw_response)

            if reasoning_part and not reasoning_prompt:
                yield f"data: {json.dumps({'type': 'reasoning', 'content': reasoning_part})}\n\n"
                await asyncio.sleep(0.1)
                yield f"data: {json.dumps({'type': 'reasoning_done'})}\n\n"

            response = answer_part if answer_part else clean_reasoning_from_response(raw_response)
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
    action = None
    target = None
    should_reason = False

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
                        timeout=300
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

        should_reason = True
        if action in ["subdomain", "full_scan", "osint", "risk", "threat_intel"]:
            scan_timeout = 300
        else:
            scan_timeout = 180

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
            should_reason = True
        else:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": request.prompt}
            ]
            return StreamingResponse(
                stream_response(messages, None),
                media_type="text/event-stream"
            )

    if not scan_data or scan_data.strip() == "No results available.":
        scan_data = "No scan data available. Please run a scan first."

    if is_list_request(request.prompt):
        print("[LLM_ROUTER] List/show request detected – returning raw data directly")
        async def data_stream():
            lines = scan_data.split('\n')
            for line in lines:
                yield f"data: {json.dumps({'type': 'response', 'content': line + chr(10)})}\n\n"
                await asyncio.sleep(0.02)
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
        return StreamingResponse(data_stream(), media_type="text/event-stream")

    if is_question(request.prompt):
        if "waf" in request.prompt.lower() or "firewall" in request.prompt.lower():
            llm_prompt = (
                f"The user asked: '{request.prompt}'\n\n"
                f"Here is the scan data from {target}:\n{scan_data}\n\n"
                f"Extract the firewall/WAF name from the scan data and output ONLY the name. "
                f"If the data says 'Firewall: Cloudflare', output 'Cloudflare'. "
                f"Do not output any other text. Just the name. If the data does not contain a firewall name, say 'Not found'.\n\n"
                f"Use this format:\n"
                f"### REASONING\n(any brief reasoning)\n"
                f"### ANSWER\n(the answer only)"
            )
        else:
            llm_prompt = (
                f"The user asked a question: '{request.prompt}'\n\n"
                f"Here is the scan data from {target}:\n{scan_data}\n\n"
                f"Based ONLY on the scan data above, answer the user's question directly and concisely. "
                f"DO NOT output the full formatted templates (like 'Found X open ports...'). "
                f"Just give the direct answer. For example, if the question is 'what WAF?', answer 'Cloudflare'.\n"
                f"If the data does not contain the answer, say 'The scan data does not contain that information.'\n\n"
                f"Use this format:\n"
                f"### REASONING\n(any brief reasoning, if needed)\n"
                f"### ANSWER\n(the answer only)"
            )
    else:
        llm_prompt = (
            f"The user requested: '{request.prompt}'\n\n"
            f"Here is the scan data from {target}:\n{scan_data}\n\n"
            f"Output the data exactly as provided, with no extra text."
        )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": llm_prompt}
    ]

    reasoning_prompt = None
    if should_reason and request.show_reasoning:
        reasoning_prompt = f"User asked: '{request.prompt}'. I performed a {action} scan on {target}. Explain your reasoning for the analysis you're about to provide."

    return StreamingResponse(
        stream_response(messages, reasoning_prompt),
        media_type="text/event-stream"
    )

@router.post("/chat")
async def chat(request: ChatRequest):
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
    action = None
    target = None
    should_reason = False

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
                        timeout=300
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

        should_reason = True
        if action in ["subdomain", "full_scan", "osint", "risk", "threat_intel"]:
            scan_timeout = 300
        else:
            scan_timeout = 180

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
            should_reason = True
        else:
            try:
                messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": request.prompt}
                ]
                result = await asyncio.wait_for(
                    llm_provider.chat(messages),
                    timeout=240,
                )
                if result.get("success"):
                    raw_response = result["response"]
                    reasoning_part = extract_reasoning_from_llm_response(raw_response)
                    answer_part = extract_answer_from_llm_response(raw_response)
                    if reasoning_part and request.show_reasoning:
                        reasoning_text = reasoning_part
                    response_text = answer_part if answer_part else clean_reasoning_from_response(raw_response)
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

    if not scan_data or scan_data.strip() == "No results available.":
        scan_data = "No scan data available. Please run a scan first."

    if is_list_request(request.prompt):
        print("[LLM_ROUTER] List/show request detected – returning raw data directly")
        return ChatResponse(
            response=scan_data,
            session_id=session_id,
            provider="local",
            scan_id=scan_id,
            reasoning=None,
        )

    if is_question(request.prompt):
        if "waf" in request.prompt.lower() or "firewall" in request.prompt.lower():
            llm_prompt = (
                f"The user asked: '{request.prompt}'\n\n"
                f"Here is the scan data from {target}:\n{scan_data}\n\n"
                f"Extract the firewall/WAF name from the scan data and output ONLY the name. "
                f"If the data says 'Firewall: Cloudflare', output 'Cloudflare'. "
                f"Do not output any other text. Just the name. If the data does not contain a firewall name, say 'Not found'.\n\n"
                f"Use this format:\n"
                f"### REASONING\n(any brief reasoning)\n"
                f"### ANSWER\n(the answer only)"
            )
        else:
            llm_prompt = (
                f"The user asked a question: '{request.prompt}'\n\n"
                f"Here is the scan data from {target}:\n{scan_data}\n\n"
                f"Based ONLY on the scan data above, answer the user's question directly and concisely. "
                f"DO NOT output the full formatted templates. Just give the direct answer.\n"
                f"If the data does not contain the answer, say 'The scan data does not contain that information.'\n\n"
                f"Use this format:\n"
                f"### REASONING\n(any brief reasoning, if needed)\n"
                f"### ANSWER\n(the answer only)"
            )
    else:
        llm_prompt = (
            f"The user requested: '{request.prompt}'\n\n"
            f"Here is the scan data from {target}:\n{scan_data}\n\n"
            f"Output the data exactly as provided, with no extra text."
        )

    try:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": llm_prompt}
        ]

        if should_reason and request.show_reasoning:
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
            raw_response = llm_result["response"]
            reasoning_part = extract_reasoning_from_llm_response(raw_response)
            answer_part = extract_answer_from_llm_response(raw_response)
            if reasoning_part and request.show_reasoning:
                reasoning_text = reasoning_part
            response_text = answer_part if answer_part else clean_reasoning_from_response(raw_response)
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
        reasoning=reasoning_text if (should_reason and request.show_reasoning) else None,
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