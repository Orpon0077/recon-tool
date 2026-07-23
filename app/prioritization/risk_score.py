"""
Risk Prioritization Engine (CTEM Framework)
All code is strictly in English.

Scoring Logic:
- Starts at 100
- Deductions based on severity:
  - CRITICAL: -20 to -25
  - HIGH: -10 to -12
  - MEDIUM: -5 to -8
  - LOW/INFO: no deduction (moved to observations)
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

SENSITIVE_PATH_KEYWORDS = [
    "/admin", "/backup", ".env", "/config", "/wp-admin",
    "/phpmyadmin", "/.git", "/api/v1",
]

SENSITIVE_SUBDOMAIN_PATTERNS = [
    "api", "admin", "backup", "demo", "staging", "db-", "-db",
    "portal", "dashboard", "dev", "test", "internal", "private",
]


def _safe_string_list(data: Any) -> List[str]:
    """
    Safely extract a list of strings from mixed data.
    Filters out dictionaries and other non-string types.
    """
    if not isinstance(data, list):
        return []

    result = []
    for item in data:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            for key in ["domain", "name", "subdomain", "host", "url"]:
                if key in item and isinstance(item[key], str):
                    result.append(item[key])
                    break
    return result


def _port_number(port_entry: Any) -> int | None:
    if isinstance(port_entry, int):
        return port_entry
    if isinstance(port_entry, dict):
        value = port_entry.get("port")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None
    return None


def _endpoint_url(endpoint: Any) -> str:
    if isinstance(endpoint, str):
        return endpoint
    if isinstance(endpoint, dict):
        return str(endpoint.get("url") or "")
    return ""


def _build_headline(overall: str, findings: List[Dict[str, str]]) -> str:
    severities = {f.get("severity", "").upper() for f in findings}
    if "CRITICAL" in severities:
        return f"{overall} overall exposure with critical configuration gaps"
    if "HIGH" in severities:
        return f"{overall} overall exposure with high-priority items to review"
    if findings:
        return f"{overall} overall exposure with actionable findings"
    return f"{overall} overall exposure with no major findings"


def calculate_risk(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate overall risk score and prioritized findings based on scan data.
    Returns risk level, score, findings with severity, and summary.
    """
    findings: List[Dict[str, str]] = []
    observations: List[Dict[str, str]] = []
    risk_score = 100

    # ========== 1. SSL Certificate ==========
    ssl = scan_results.get("ssl", {})
    if isinstance(ssl, dict):
        days = ssl.get("days_remaining") or ssl.get("days_left")
        try:
            days = int(days) if days is not None else None
            if days is not None:
                if days < 0:
                    findings.append({
                        "severity": "CRITICAL",
                        "description": "SSL certificate has expired.",
                        "recommendation": "Renew the SSL certificate immediately."
                    })
                    risk_score -= 25
                elif days < 30:
                    findings.append({
                        "severity": "HIGH",
                        "description": f"SSL certificate expires in {days} days.",
                        "recommendation": "Renew the SSL certificate within 2 weeks."
                    })
                    risk_score -= 15
                elif days < 90:
                    findings.append({
                        "severity": "MEDIUM",
                        "description": f"SSL certificate expires in {days} days.",
                        "recommendation": "Plan to renew the SSL certificate."
                    })
                    risk_score -= 5
        except (ValueError, TypeError):
            pass

    # ========== 2. Security Headers ==========
    headers = scan_results.get("security_headers", {})
    if isinstance(headers, dict):
        score = headers.get("score")
        try:
            score = int(score) if score is not None else None
            if score is not None:
                if score < 50:
                    findings.append({
                        "severity": "CRITICAL",
                        "description": f"Security headers score is {score}/100. Missing HSTS or CSP.",
                        "recommendation": "Implement HSTS, CSP, X-Frame-Options, and X-Content-Type-Options."
                    })
                    risk_score -= 20
                elif score < 80:
                    findings.append({
                        "severity": "HIGH",
                        "description": f"Security headers score is {score}/100. Some headers missing.",
                        "recommendation": "Review and add missing security headers (e.g., Referrer-Policy)."
                    })
                    risk_score -= 10
        except (ValueError, TypeError):
            pass

    # ========== 3. Open Ports ==========
    ports_data = scan_results.get("ports", {})
    open_ports = []
    if isinstance(ports_data, dict):
        open_ports = ports_data.get("open_ports", [])
    elif isinstance(ports_data, list):
        open_ports = ports_data

    critical_ports = [3306, 5432, 27017, 6379, 1433, 1521]
    high_ports = [22, 3389, 5900, 5800]

    for port_entry in open_ports:
        port = _port_number(port_entry)
        if port is None:
            continue
        if port in critical_ports:
            findings.append({
                "severity": "CRITICAL",
                "description": f"Database or critical service port {port} is exposed.",
                "recommendation": "Restrict access to this port using a firewall or VPN.",
            })
            risk_score -= 25
            break
        elif port in high_ports:
            findings.append({
                "severity": "HIGH",
                "description": f"Administrative port {port} is open (SSH/RDP/VNC).",
                "recommendation": "Use strong authentication, key-based access, or limit source IPs.",
            })
            risk_score -= 10
            break
        elif port not in [80, 443, 8080, 8443]:
            findings.append({
                "severity": "MEDIUM",
                "description": f"Non-standard port {port} is open.",
                "recommendation": "Verify if this port is required. If not, close it.",
            })
            risk_score -= 5
            break

    # ========== 4. CDN / WAF Detection ==========
    firewall = scan_results.get("firewall", {})
    if isinstance(firewall, dict):
        cdn_detected = firewall.get("cdn_detected")
        waf_detected = firewall.get("waf_detected")
        fw_name = firewall.get("firewall_name") or firewall.get("name", "Unknown")
        cdn_name = firewall.get("cdn_name")
        waf_name = firewall.get("waf_name")

        if cdn_detected is None and waf_detected is None:
            cdn_services = ["CloudFront", "Cloudflare", "Fastly", "Akamai", "Amazon CloudFront"]
            cdn_detected = any(cdn in fw_name for cdn in cdn_services) if firewall.get("detected") else False
            waf_detected = bool(firewall.get("detected")) and not cdn_detected

        if cdn_detected:
            observations.append({
                "severity": "INFO",
                "description": f"CDN detected: {cdn_name or fw_name}",
                "recommendation": "CDN improves delivery but does not replace WAF or security headers.",
            })

        if waf_detected:
            observations.append({
                "severity": "INFO",
                "description": f"WAF detected: {waf_name or fw_name}",
                "recommendation": "Ensure WAF rules are updated and properly tuned for your application.",
            })

        if not cdn_detected and not waf_detected and firewall.get("detected") is False:
            findings.append({
                "severity": "MEDIUM",
                "description": "No CDN or WAF protection layer detected.",
                "recommendation": "Consider deploying a CDN and WAF (Cloudflare, AWS WAF, ModSecurity).",
            })
            risk_score -= 10

    # ========== 5. Subdomains & Attack Surface (LIVE ONLY) ==========
    active_subs_raw = scan_results.get("subdomains", {})
    all_subdomains = []
    if isinstance(active_subs_raw, dict):
        all_subdomains = active_subs_raw.get("subdomains", [])
    elif isinstance(active_subs_raw, list):
        all_subdomains = active_subs_raw

    live_subdomains = []
    for s in all_subdomains:
        if isinstance(s, dict) and s.get("resolved", False):
            live_subdomains.append(s)

    live_sub_names = []
    for s in live_subdomains:
        if isinstance(s, dict):
            name = s.get("subdomain") or s.get("name")
            if name:
                live_sub_names.append(name)

    osint_data = scan_results.get("osint", {})
    crt_subs = []
    if isinstance(osint_data, dict):
        crt_subs = _safe_string_list(osint_data.get("crt_subdomains", []))

    try:
        all_subs_set = set(live_sub_names) | set(crt_subs)
        total_subs = len(all_subs_set)

        if total_subs > 100:
            findings.append({
                "severity": "HIGH",
                "description": f"Large live attack surface: {total_subs} active subdomains discovered.",
                "recommendation": "Review all subdomains, remove unnecessary ones, monitor for typosquatting."
            })
            risk_score -= 15
        elif total_subs > 30:
            findings.append({
                "severity": "MEDIUM",
                "description": f"Moderate live attack surface: {total_subs} active subdomains discovered.",
                "recommendation": "Regularly audit subdomains for shadow IT."
            })
            risk_score -= 5

        sensitive_live = [s for s in live_subdomains if s.get("sensitive", False)]
        if sensitive_live:
            sensitive_names = [s.get("subdomain") for s in sensitive_live[:5]]
            findings.append({
                "severity": "HIGH" if len(sensitive_live) > 5 else "MEDIUM",
                "description": f"Sensitive live subdomains found: {', '.join(sensitive_names)}",
                "recommendation": "Ensure these subdomains have proper access controls, authentication, and monitoring."
            })
            risk_score -= 10 if len(sensitive_live) > 5 else 5

    except TypeError:
        logger.warning("Could not build subdomain set due to unhashable types. Skipping subdomain risk.")

    # ========== 6. Sensitive Paths ==========
    sensitive_paths = []
    crawl = scan_results.get("crawl", {})
    if isinstance(crawl, dict):
        endpoints = crawl.get("endpoints", [])
        if isinstance(endpoints, list):
            for ep in endpoints:
                url_value = _endpoint_url(ep)
                if url_value and any(x in url_value.lower() for x in SENSITIVE_PATH_KEYWORDS):
                    sensitive_paths.append(url_value)

    if isinstance(osint_data, dict):
        wayback = osint_data.get("wayback_urls", [])
        if isinstance(wayback, list):
            for url_path in wayback:
                if isinstance(url_path, str):
                    if any(x in url_path.lower() for x in ["/admin", "/backup", ".env", "/config", "/wp-admin", "/phpmyadmin", "/.git"]):
                        if url_path not in sensitive_paths:
                            sensitive_paths.append(url_path)

    if sensitive_paths:
        findings.append({
            "severity": "CRITICAL",
            "description": f"Sensitive endpoints found: {', '.join(sensitive_paths[:3])}",
            "recommendation": "Restrict access to these paths, remove exposed backups, and secure admin panels."
        })
        risk_score -= 30

    # ========== 7. JavaScript Analysis (Confidence-based severity) ==========
    js_data = scan_results.get("js_scanner", scan_results.get("js", {}))
    if isinstance(js_data, dict) and not js_data.get("error"):
        tokens = js_data.get("tokens", [])
        path_leakage = js_data.get("path_leakage", [])
        source_maps = js_data.get("source_maps", [])
        internal_paths = js_data.get("internal_paths", [])

        # Count tokens by confidence level
        high_confidence_tokens = [t for t in tokens if t.get("confidence") == "high"]
        medium_confidence_tokens = [t for t in tokens if t.get("confidence") == "medium"]
        low_confidence_tokens = [t for t in tokens if t.get("confidence") == "low"]

        # High confidence → CRITICAL
        if high_confidence_tokens:
            findings.append({
                "severity": "CRITICAL",
                "description": f"High-confidence secrets found in JavaScript ({len(high_confidence_tokens)} match(es)).",
                "recommendation": "Rotate exposed credentials and remove secrets from client-side bundles.",
            })
            risk_score -= 25

        # Medium confidence → HIGH
        if medium_confidence_tokens:
            findings.append({
                "severity": "HIGH",
                "description": f"Medium-confidence potential secrets found in JavaScript ({len(medium_confidence_tokens)} match(es)). Review to confirm.",
                "recommendation": "Verify if these are real credentials. If false positives, adjust scanner patterns.",
            })
            risk_score -= 12

        # Low confidence → Observations (INFO)
        if low_confidence_tokens:
            observations.append({
                "severity": "INFO",
                "description": f"Low-confidence potential tokens found in JavaScript ({len(low_confidence_tokens)} match(es)). Likely false positives or internal framework strings.",
                "recommendation": "Review scanner output. These may be Next.js internals or CSS variables.",
            })
            # No risk score deduction for low confidence

        # Path leakage detection (Fix #4)
        if not path_leakage:
            for p in internal_paths:
                if any(x in p.lower() for x in ["node_modules", "root", "dist", "build", "src", "lib"]):
                    path_leakage.append(p)

        if path_leakage:
            findings.append({
                "severity": "MEDIUM",
                "description": f"Build path leakage in JavaScript: {', '.join(path_leakage[:3])}",
                "recommendation": "Review bundler output and disable source maps in production.",
            })
            risk_score -= 8

        if source_maps:
            observations.append({
                "severity": "INFO",
                "description": f"Source maps exposed in {len(source_maps)} JavaScript file(s).",
                "recommendation": "Remove public source maps unless intentionally published.",
            })

    # ========== 8. Threat Intelligence ==========
    threat = scan_results.get("threat_intel", {})
    if isinstance(threat, dict):
        summary = threat.get("summary", {})
        malicious_count = summary.get("malicious_count", 0)
        high_risk_count = summary.get("high_risk_count", 0)

        if malicious_count > 0 or high_risk_count > 0:
            severity = "CRITICAL" if malicious_count > 3 else "HIGH"
            findings.append({
                "severity": severity,
                "description": f"Threat Intelligence: {malicious_count} malicious and {high_risk_count} high-risk entities detected.",
                "recommendation": "Review these entities. Block if necessary. Check your perimeter security.",
            })
            risk_score -= 20 if malicious_count > 3 else 10

    # ========== 9. Subdomain Summary (Observation) ==========
    subdomain_data = scan_results.get("subdomains", {})
    if isinstance(subdomain_data, dict):
        total = subdomain_data.get("total_found", 0)
        live = subdomain_data.get("live_count", 0)
        dead = subdomain_data.get("dead_count", 0)
        zombie = subdomain_data.get("zombie_count", 0)
        parsing_errors = subdomain_data.get("parsing_error_count", 0)
        filtered = subdomain_data.get("filtered_entries", [])

        if total > 0:
            obs_text = f"Subdomains: {total} total (🟢 {live} live · ⚫ {dead} dead · 🟡 {zombie} zombie)"
            if parsing_errors > 0:
                obs_text += f" ⚠️ {parsing_errors} parsing errors detected"
            if filtered:
                obs_text += f" | {len(filtered)} entries filtered as malformed"
                examples = [f["subdomain"] for f in filtered[:3]]
                if examples:
                    obs_text += f" (e.g., {', '.join(examples)})"
            observations.append({
                "severity": "INFO",
                "description": obs_text,
                "recommendation": "Review dead subdomains for removal, zombie subdomains for takeover risk, and parsing errors for malformed entries.",
            })

    # ========== 10. Final Classification ==========
    risk_score = max(0, min(100, risk_score))

    if risk_score < 30:
        overall = "CRITICAL"
    elif risk_score < 55:
        overall = "HIGH"
    elif risk_score < 75:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in summary:
            summary[sev] += 1

    return {
        "overall_risk": overall,
        "score": risk_score,
        "headline": _build_headline(overall, findings),
        "findings": findings,
        "observations": observations,
        "summary": summary,
        "total_findings": len(findings),
        "ctem_phase": "Prioritization",
    }