from datetime import datetime
import os


def generate_pdf_report(data: dict, url: str) -> str:
    """
    Professional HTML report – view in browser and print to PDF.
    Now includes OSINT, CTEM Risk Prioritization (with Charts), and Threat Intelligence.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recon_report_{timestamp}.html"
    filepath = os.path.join("static", "reports", filename)
    os.makedirs(os.path.join("static", "reports"), exist_ok=True)

    # ── Extract data ──
    ssl_data = data.get("ssl", {}) or {}
    headers_data = data.get("security_headers", data.get("headers", {})) or {}
    ports_data = data.get("ports", {}) or {}
    firewall_data = data.get("firewall", {}) or {}
    tech_data = data.get("tech", {}) or {}
    crawl_data = data.get("crawl", {}) or {}
    subdomain_data = data.get("subdomains", {}) or {}
    js_data = data.get("js_scanner", data.get("js", {})) or {}
    screenshot_data = data.get("screenshot", {}) or {}
    osint_data = data.get("osint", {}) or {}
    risk_data = data.get("risk", {}) or {}
    threat_data = data.get("threat_intel", {}) or {}

    # ── SSL section ── (unchanged)
    ssl_html = ""
    if ssl_data and not ssl_data.get("error"):
        days = ssl_data.get("days_remaining", "N/A")
        expired = ssl_data.get("is_expired", False)
        days_color = "#00aa55" if isinstance(days, int) and days > 30 else "#ff4444"
        ssl_html = f"""
        <div class="section">
            <h2>🔒 SSL/TLS Analysis</h2>
            <table>
                <tr><th>Field</th><th>Value</th></tr>
                <tr><td>Issued To</td><td>{ssl_data.get('issued_to', 'N/A')}</td></tr>
                <tr><td>Issued By</td><td>{ssl_data.get('issued_by', 'N/A')}</td></tr>
                <tr><td>Valid From</td><td>{ssl_data.get('valid_from', 'N/A')}</td></tr>
                <tr><td>Valid Until</td><td>{ssl_data.get('valid_until', 'N/A')}</td></tr>
                <tr><td>Days Remaining</td><td style="color:{days_color}; font-weight:bold;">{days}</td></tr>
                <tr><td>Expired</td><td style="color:{'#ff4444' if expired else '#00aa55'}; font-weight:bold;">{'YES ⚠️' if expired else 'NO ✓'}</td></tr>
            </table>
        </div>
        """
    else:
        ssl_html = f'<div class="section"><h2>🔒 SSL/TLS Analysis</h2><p class="error">Error: {ssl_data.get("error", "No data available")}</p></div>'

    # ── Security Headers ── (unchanged)
    headers_html = ""
    if headers_data and not headers_data.get("error"):
        score = headers_data.get("score", 0)
        present = headers_data.get("present", {})
        missing = headers_data.get("missing", [])
        score_color = "#00aa55" if score >= 70 else "#ff8800" if score >= 40 else "#ff4444"
        present_rows = "".join([f'<tr><td style="color:#00aa55;">✓ {h}</td><td>{v[:80]}</td></tr>' for h, v in present.items()])
        missing_rows = "".join([f'<tr><td style="color:#ff4444;">✗ {h}</td><td style="color:#ff4444;">MISSING</td></tr>' for h in missing])
        headers_html = f"""
        <div class="section">
            <h2>🛡️ Security Headers</h2>
            <div class="score-badge" style="background:{score_color};">Security Score: {score}/100</div>
            <table>
                <tr><th>Header</th><th>Value / Status</th></tr>
                {present_rows}
                {missing_rows}
            </table>
        </div>
        """
    else:
        headers_html = f'<div class="section"><h2>🛡️ Security Headers</h2><p class="error">Error: {headers_data.get("error", "No data available")}</p></div>'

    # ── Port Scanning ── (unchanged)
    ports_html = ""
    if ports_data and not ports_data.get("error"):
        open_ports = ports_data.get("open_ports", [])
        if open_ports:
            port_rows = "".join([
                f'<tr><td style="font-weight:bold;">{p.get("port", "")}</td><td>{p.get("service", "unknown")}</td><td style="color:#00aa55;">OPEN</td><td>{p.get("version", "unknown")}</td></tr>'
                for p in open_ports
            ])
            ports_html = f"""
            <div class="section">
                <h2>🔍 Port Scanning</h2>
                <p>Total open ports: <strong>{len(open_ports)}</strong></p>
                <table>
                    <tr><th>Port</th><th>Service</th><th>State</th><th>Version</th></tr>
                    {port_rows}
                </table>
            </div>
            """
        else:
            ports_html = '<div class="section"><h2>🔍 Port Scanning</h2><p>No open ports found.</p></div>'
    else:
        ports_html = f'<div class="section"><h2>🔍 Port Scanning</h2><p class="error">Error: {ports_data.get("error", "No data available")}</p></div>'

    # ── Firewall / CDN Detection ── (unchanged)
    firewall_html = ""
    if firewall_data and not firewall_data.get("error"):
        detected = firewall_data.get("detected", False)
        fw_name = firewall_data.get("firewall_name", "Unknown")
        evidence = firewall_data.get("evidence", "N/A")
        cdn_detected = firewall_data.get("cdn_detected", False)
        waf_detected = firewall_data.get("waf_detected", False)
        cdn_name = firewall_data.get("cdn_name") or fw_name
        waf_name = firewall_data.get("waf_name") or fw_name

        rows = [
            f'<tr><td>Protection Layer</td><td style="font-weight:bold;">{"Detected" if detected else "Not Detected"}</td></tr>',
            f'<tr><td>CDN</td><td style="color:{"#00aa55" if cdn_detected else "#888"};">{"YES ✓" if cdn_detected else "NO"}</td></tr>',
        ]
        if cdn_detected:
            rows.append(f'<tr><td>CDN Name</td><td>{cdn_name}</td></tr>')
        rows.append(
            f'<tr><td>WAF</td><td style="color:{"#00aa55" if waf_detected else "#ff8800"};">'
            f'{"YES ✓" if waf_detected else "NO"}</td></tr>'
        )
        if waf_detected:
            rows.append(f'<tr><td>WAF Name</td><td>{waf_name}</td></tr>')
        rows.append(f'<tr><td>Evidence</td><td>{evidence}</td></tr>')

        firewall_html = f"""
        <div class="section">
            <h2>🔥 CDN / WAF Detection</h2>
            <table>
                <tr><th>Field</th><th>Value</th></tr>
                {''.join(rows)}
            </table>
        </div>
        """
    else:
        firewall_html = f'<div class="section"><h2>🔥 CDN / WAF Detection</h2><p class="error">Error: {firewall_data.get("error", "No data")}</p></div>'

    # ── Technology Detection ── (unchanged)
    tech_html = ""
    if tech_data and not tech_data.get("error"):
        technologies = tech_data.get("technologies", {})
        total = tech_data.get("total_found", 0)
        if technologies:
            tech_rows = "".join([
                f'<tr><td style="font-weight:bold;">{cat}</td><td>{", ".join(items)}</td></tr>'
                for cat, items in technologies.items()
            ])
            tech_html = f"""
            <div class="section">
                <h2>⚙️ Technology Detection</h2>
                <p>Total technologies found: <strong>{total}</strong></p>
                <table>
                    <tr><th>Category</th><th>Technologies</th></tr>
                    {tech_rows}
                </table>
            </div>
            """
        else:
            tech_html = '<div class="section"><h2>⚙️ Technology Detection</h2><p>No technologies detected.</p></div>'
    else:
        tech_html = f'<div class="section"><h2>⚙️ Technology Detection</h2><p class="error">Error: {tech_data.get("error", "No data")}</p></div>'

    # ── Crawling ── (unchanged)
    crawl_html = ""
    if crawl_data and not crawl_data.get("error"):
        endpoints = crawl_data.get("endpoints", [])
        if endpoints:
            endpoint_rows = "".join([
                f'<tr><td style="word-break:break-all;">{e.get("url", "")}</td><td>{e.get("method", "GET")}</td><td style="color:{"#00aa55" if str(e.get("status_code","")).startswith("2") else "#ff4444"};">{e.get("status_code", "N/A")}</td><td>{e.get("content_type", "")}</td></tr>'
                for e in endpoints[:50]
            ])
            crawl_html = f"""
            <div class="section">
                <h2>🕷️ Crawling / Endpoint Discovery</h2>
                <p>Total endpoints found: <strong>{len(endpoints)}</strong></p>
                <table>
                    <tr><th>URL</th><th>Method</th><th>Status</th><th>Content Type</th></tr>
                    {endpoint_rows}
                </table>
            </div>
            """
        else:
            crawl_html = '<div class="section"><h2>🕷️ Crawling / Endpoint Discovery</h2><p>No endpoints found.</p></div>'
    else:
        crawl_html = f'<div class="section"><h2>🕷️ Crawling / Endpoint Discovery</h2><p class="error">Error: {crawl_data.get("error", "No data")}</p></div>'

    # ── Subdomains ── (unchanged)
    subdomain_html = ""
    if subdomain_data and not subdomain_data.get("error"):
        subdomains = subdomain_data.get("subdomains", [])
        total = subdomain_data.get("total_found", len(subdomains))
        if subdomains:
            sub_rows = "".join([
                f'<tr>'
                f'<td>{s.get("subdomain", "") if isinstance(s, dict) else s}</td>'
                f'<td>{s.get("ip", "N/A") if isinstance(s, dict) else "N/A"}</td>'
                f'<td>{s.get("http_status", "N/A") if isinstance(s, dict) else "N/A"}</td>'
                f'<td style="color:{"#ff4444" if isinstance(s, dict) and s.get("sensitive") else "#888"};">'
                f'{"YES" if isinstance(s, dict) and s.get("sensitive") else "NO"}</td>'
                f'<td>{s.get("source", "unknown")}</td>'
                f'</tr>'
                for s in subdomains[:100]
            ])
            sensitive_count = subdomain_data.get("sensitive_count") or sum(
                1 for s in subdomains if isinstance(s, dict) and s.get("sensitive")
            )
            subdomain_html = f"""
            <div class="section">
                <h2>🌐 Subdomain Discovery</h2>
                <p>Total subdomains found: <strong>{total}</strong> · Sensitive names: <strong>{sensitive_count}</strong></p>
                <table>
                    <tr><th>Subdomain</th><th>IP Address</th><th>HTTP Status</th><th>Sensitive</th><th>Source</th></tr>
                    {sub_rows}
                </table>
            </div>
            """
        else:
            subdomain_html = '<div class="section"><h2>🌐 Subdomain Discovery</h2><p>No subdomains found.</p></div>'
    else:
        subdomain_html = f'<div class="section"><h2>🌐 Subdomain Discovery</h2><p class="error">Error: {subdomain_data.get("error", "No data")}</p></div>'

    # ── JS Analysis (UPDATED with confidence & context) ──
    js_html = ""
    if js_data and not js_data.get("error"):
        total_js = js_data.get("total_js_files", js_data.get("total", 0))
        vulnerabilities = js_data.get("vulnerabilities", [])
        emails = js_data.get("emails", [])
        api_endpoints = js_data.get("api_endpoints", [])
        internal_paths = js_data.get("internal_paths", [])
        path_leakage = js_data.get("path_leakage", [])
        tokens = js_data.get("tokens", [])
        source_maps = js_data.get("source_maps", [])

        js_content = f"<p>Total JS files: <strong>{total_js}</strong></p>"
        if emails:
            js_content += f"<p><strong>Emails found:</strong> {', '.join(emails[:10])}</p>"
        if api_endpoints:
            js_content += f"<p><strong>API Endpoints:</strong></p><ul>{''.join(['<li>' + e + '</li>' for e in api_endpoints[:20]])}</ul>"
        if internal_paths:
            js_content += f"<p><strong>Internal Paths:</strong></p><ul>{''.join(['<li>' + p + '</li>' for p in internal_paths[:20]])}</ul>"
        if path_leakage:
            js_content += f"<p><strong>Build Path Leakage:</strong> {', '.join(path_leakage[:10])}</p>"
        if source_maps:
            js_content += f"<p><strong>Source maps found:</strong> {len(source_maps)}</p>"
        if vulnerabilities:
            vuln_rows = "".join([f'<tr><td>{v.get("file", "")}</td><td style="color:#ff4444;">{v.get("pattern", "")}</td></tr>' for v in vulnerabilities[:20]])
            js_content += f"<p><strong>Potential Issues ({len(vulnerabilities)}):</strong></p><table><tr><th>File</th><th>Pattern</th></tr>{vuln_rows}</table>"

        # বাংলা: টোকেন দেখানোর সময় কনফিডেন্স ও কনটেক্সট যোগ করা হলো
        if tokens:
            js_content += "<p><strong>🔑 Potential Secrets/Tokens:</strong></p><table><tr><th>Value</th><th>Confidence</th><th>Context Snippet</th></tr>"
            for token in tokens[:10]:
                value = token.get('value', 'N/A')
                confidence = token.get('confidence', 'unknown')
                context = token.get('context', 'N/A')[:80] + "..." if token.get('context') else "N/A"
                confidence_color = "#00aa55" if confidence == "high" else "#ff8800" if confidence == "medium" else "#ff4444"
                js_content += f"<tr><td><code style='background:#f0f0f0;padding:2px 4px;'>{value}</code></td><td style='color:{confidence_color};font-weight:bold;'>{confidence}</td><td style='font-size:0.8rem;color:#555;'>{context}</td></tr>"
            js_content += "</table>"

        js_html = f'<div class="section"><h2>📜 JavaScript Analysis</h2>{js_content}</div>'
    else:
        js_html = f'<div class="section"><h2>📜 JavaScript Analysis</h2><p class="error">Error: {js_data.get("error", "No data")}</p></div>'

    # ── Screenshot ── (unchanged)
    screenshot_html = ""
    if screenshot_data and not screenshot_data.get("error"):
        path = screenshot_data.get("screenshot_path", "")
        if path:
            img_src = path if path.startswith("/") else f"/static/{path.lstrip('/')}"
            screenshot_html = f"""
            <div class="section">
                <h2>📸 Screenshot</h2>
                <img src="{img_src}" alt="Screenshot of {url}" style="max-width:100%; border:1px solid #ddd; border-radius:4px;">
            </div>
            """
        else:
            screenshot_html = '<div class="section"><h2>📸 Screenshot</h2><p>No screenshot available.</p></div>'
    else:
        screenshot_html = f'<div class="section"><h2>📸 Screenshot</h2><p class="error">Error: {screenshot_data.get("error", "No data")}</p></div>'

    # ── OSINT Section ── (unchanged)
    osint_html = ""
    if osint_data and not osint_data.get("error"):
        whois = osint_data.get("whois", {})
        dns = osint_data.get("dns_records", {})
        wayback = osint_data.get("wayback_urls", [])
        crt = osint_data.get("crt_subdomains", [])

        osint_content = ""
        if whois and not whois.get("error"):
            osint_content += f"""
            <h3>📋 WHOIS Information</h3>
            <table>
                <tr><th>Field</th><th>Value</th></tr>
                <tr><td>Registrar</td><td>{whois.get('registrar', 'N/A')}</td></tr>
                <tr><td>Creation Date</td><td>{whois.get('creation_date', 'N/A')}</td></tr>
                <tr><td>Expiration Date</td><td>{whois.get('expiration_date', 'N/A')}</td></tr>
                <tr><td>Name Servers</td><td>{', '.join(whois.get('name_servers', []))}</td></tr>
            </table>
            """
        else:
            osint_content += f"<p class='error'>WHOIS: {whois.get('error', 'No data')}</p>"

        if dns and any(values for values in dns.values()):
            osint_content += "<h3>🌐 DNS Records</h3><table><tr><th>Type</th><th>Values</th></tr>"
            for qtype, values in dns.items():
                if values:
                    osint_content += f"<tr><td>{qtype}</td><td>{', '.join(values)}</td></tr>"
            osint_content += "</table>"
        elif osint_data.get("dns_available") is False:
            osint_content += "<p>DNS lookup unavailable (install dnspython).</p>"
        else:
            osint_content += "<p>No DNS records retrieved.</p>"

        if wayback:
            osint_content += f"<h3>📜 Wayback Machine URLs ({len(wayback)} found)</h3><ul>"
            for w in wayback[:20]:
                osint_content += f"<li>{w}</li>"
            if len(wayback) > 20:
                osint_content += f"<li>... and {len(wayback)-20} more</li>"
            osint_content += "</ul>"
        else:
            osint_content += "<p>No Wayback URLs found.</p>"

        if crt:
            osint_content += f"<h3>🔍 crt.sh Subdomains ({len(crt)} found)</h3><ul>"
            for sub in crt[:30]:
                osint_content += f"<li>{sub}</li>"
            if len(crt) > 30:
                osint_content += f"<li>... and {len(crt)-30} more</li>"
            osint_content += "</ul>"
        else:
            osint_content += "<p>No crt.sh subdomains found.</p>"

        osint_html = f"""
        <div class="section" style="border-left-color: #6f42c1;">
            <h2>🌍 Open Source Intelligence (OSINT)</h2>
            {osint_content}
        </div>
        """
    else:
        osint_html = f'<div class="section"><h2>🌍 Open Source Intelligence (OSINT)</h2><p class="error">Error: {osint_data.get("error", "No data")}</p></div>'

    # ── Risk Prioritization (CTEM) Section WITH CHARTS AND LEGEND ──
    risk_html = ""
    if risk_data and not risk_data.get("error"):
        overall = risk_data.get("overall_risk", "UNKNOWN")
        score = risk_data.get("score", 0)
        headline = risk_data.get("headline", "")
        findings = risk_data.get("findings", [])
        observations = risk_data.get("observations", [])
        summary = risk_data.get("summary", {})
        total_findings = risk_data.get("total_findings", 0)

        critical_count = summary.get('critical', 0)
        high_count = summary.get('high', 0)
        medium_count = summary.get('medium', 0)
        low_count = summary.get('low', 0)

        risk_color = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "UNKNOWN": "#6c757d"
        }.get(overall.upper(), "#6c757d")

        # ── বাংলা: স্কোর লিজেন্ড যোগ করা হলো ──
        risk_content = f"""
        <div style="background: #f0f4f8; padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: 0.9rem; border-left: 4px solid #0f3460;">
            <strong>📌 Score Legend:</strong><br>
            • <strong>Security Headers Score</strong> – reflects only the security headers (HSTS, CSP, etc.).<br>
            • <strong>CTEM Overall Risk Score</strong> – weighted score considering SSL, ports, subdomains, JavaScript, threat intelligence, and more.
        </div>
        """

        risk_content += f"""
        <div style="display:flex; align-items:center; gap:20px; flex-wrap:wrap; margin-bottom:16px;">
            <div style="background:{risk_color}; color:white; padding:12px 24px; border-radius:8px; font-weight:bold; font-size:1.3rem;">
                Overall Risk: {overall}
            </div>
            <div style="background:#1a1a2e; color:white; padding:12px 24px; border-radius:8px; font-weight:bold; font-size:1.1rem;">
                Score: {score}/100
            </div>
        </div>
        """
        if headline:
            risk_content += f'<p style="margin-bottom:12px; color:#555;"><em>{headline}</em></p>'

        # Charts Section
        risk_content += """
        <div style="display: flex; flex-wrap: wrap; justify-content: space-around; align-items: center; background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <div style="width: 200px; height: 200px; text-align: center;">
                <canvas id="riskPieChart"></canvas>
                <p style="font-size: 0.7rem; color: #888; margin-top: 5px;">Severity Breakdown</p>
            </div>
            <div style="width: 250px; text-align: center;">
                <p style="font-size: 0.8rem; font-weight: bold; margin-bottom: 5px;">Risk Score</p>
                <div style="width: 100%; background: #e9ecef; border-radius: 10px; height: 25px; overflow: hidden; border: 1px solid #ddd;">
                    <div id="scoreGaugeBar" style="width: """ + str(score) + """%; height: 100%; background: """ + risk_color + """; border-radius: 10px; transition: width 0.5s; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 0.7rem;">
                        """ + str(score) + """/100
                    </div>
                </div>
                <p style="font-size: 0.6rem; color: #888; margin-top: 3px;">0 ———————————— 100</p>
            </div>
        </div>
        """

        if summary:
            risk_content += f"""
            <table>
                <tr><th>Severity</th><th>Count</th></tr>
                <tr><td style="color:#dc3545;">Critical</td><td>{critical_count}</td></tr>
                <tr><td style="color:#fd7e14;">High</td><td>{high_count}</td></tr>
                <tr><td style="color:#ffc107;">Medium</td><td>{medium_count}</td></tr>
                <tr><td style="color:#28a745;">Low</td><td>{low_count}</td></tr>
            </table>
            """

        if findings:
            risk_content += f"<p><strong>Findings ({total_findings}):</strong></p><ul>"
            for f in findings[:10]:
                sev = f.get('severity', 'Info')
                desc = f.get('description', '')
                rec = f.get('recommendation', '')
                risk_content += f"<li><strong>[{sev}]</strong> {desc}<br><span style='font-size:0.85rem; color:#888;'>💡 {rec}</span></li>"
            if len(findings) > 10:
                risk_content += f"<li>... and {len(findings)-10} more findings</li>"
            risk_content += "</ul>"
        else:
            risk_content += "<p>No significant findings. Security posture appears good.</p>"

        if observations:
            risk_content += f"<p><strong>Observations:</strong></p><ul>"
            for obs in observations[:5]:
                risk_content += f"<li><span style='color:#6c757d;'>[{obs.get('severity', 'Info')}]</span> {obs.get('description', '')}</li>"
            risk_content += "</ul>"

        risk_html = f"""
        <div class="section" style="border-left-color: {risk_color};">
            <h2>📊 CTEM Prioritization (Risk Assessment)</h2>
            {risk_content}
        </div>
        """
    else:
        risk_html = f'<div class="section"><h2>📊 CTEM Prioritization</h2><p class="error">Error: {risk_data.get("error", "No risk data")}</p></div>'

    # ── Threat Intelligence Section ── (unchanged)
    threat_html = ""
    if threat_data and not threat_data.get("error"):
        summary = threat_data.get("summary", {})
        malicious = threat_data.get("malicious_entities", [])
        high_risk = threat_data.get("high_risk_entities", [])
        details = threat_data.get("details", {})

        threat_content = f"""
        <h3>📊 Summary</h3>
        <table>
            <tr><th>Metric</th><th>Count</th></tr>
            <tr><td>Entities Checked</td><td>{summary.get('total_entities', 0)}</td></tr>
            <tr><td>Malicious Entities</td><td style="color:#ff4444;">{summary.get('malicious_count', 0)}</td></tr>
            <tr><td>High-Risk Entities</td><td style="color:#ff8800;">{summary.get('high_risk_count', 0)}</td></tr>
        </table>
        """
        if malicious:
            threat_content += f"<p><strong>⚠️ Malicious Entities:</strong> {', '.join(malicious[:10])}</p>"
        if high_risk:
            threat_content += f"<p><strong>🔥 High-Risk Entities:</strong> {', '.join(high_risk[:10])}</p>"

        scored = []
        for entity, entity_data in details.items():
            if isinstance(entity_data, dict) and "risk_score" in entity_data:
                scored.append((entity, entity_data["risk_score"]))
        scored.sort(key=lambda x: x[1], reverse=True)
        if scored:
            threat_content += "<h3>📊 Top Risk Scores</h3><table><tr><th>Entity</th><th>Risk Score</th></tr>"
            for entity, score in scored[:5]:
                color = "#ff4444" if score > 70 else "#ff8800" if score > 40 else "#00aa55"
                threat_content += f"<tr><td>{entity}</td><td style='color:{color}; font-weight:bold;'>{score}/100</td></tr>"
            threat_content += "</table>"

        threat_html = f"""
        <div class="section" style="border-left-color: #8b0000;">
            <h2>🛡️ Threat Intelligence</h2>
            {threat_content}
        </div>
        """
    else:
        threat_html = f'<div class="section"><h2>🛡️ Threat Intelligence</h2><p class="error">No threat data available</p></div>'

    # ── Full HTML Layout ──
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report — {url}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f8f9fa;
            color: #333;
            font-size: 14px;
            line-height: 1.6;
        }}
        .report-header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .report-header h1 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: 0.05em;
        }}
        .report-header .subtitle {{
            font-size: 1rem;
            opacity: 0.8;
            margin-bottom: 16px;
        }}
        .report-header .meta {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }}
        .report-header .meta-item {{
            background: rgba(255,255,255,0.1);
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 0.85rem;
        }}
        .report-body {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px 20px;
        }}
        .section {{
            background: white;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border-left: 4px solid #0f3460;
            page-break-inside: avoid;
        }}
        .section h2 {{
            font-size: 1.2rem;
            color: #1a1a2e;
            margin-bottom: 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }}
        .section h3 {{
            font-size: 1.05rem;
            margin-top: 16px;
            margin-bottom: 10px;
            color: #0f3460;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 0.88rem;
        }}
        th {{
            background: #1a1a2e;
            color: white;
            padding: 10px 14px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 9px 14px;
            border-bottom: 1px solid #f0f0f0;
            word-break: break-word;
        }}
        tr:hover td {{
            background: #f8f9fa;
        }}
        .score-badge {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 1rem;
            margin-bottom: 16px;
        }}
        .error {{
            color: #ff4444;
            font-style: italic;
        }}
        ul {{ padding-left: 20px; margin: 8px 0; }}
        li {{ margin: 4px 0; }}
        .print-btn {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #0f3460;
            color: white;
            border: none;
            padding: 14px 28px;
            border-radius: 50px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: all 0.2s;
        }}
        .print-btn:hover {{ background: #16213e; transform: translateY(-2px); }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .summary-card .number {{
            font-size: 2rem;
            font-weight: 700;
            color: #0f3460;
        }}
        .summary-card .label {{
            font-size: 0.75rem;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 4px;
        }}
        .report-footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 0.75rem;
            color: #888;
        }}
        @media print {{
            .print-btn {{ display: none; }}
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ddd; page-break-inside: avoid; }}
            .summary-grid {{ page-break-inside: avoid; }}
            @page {{
                margin: 1.5cm;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🔍 Web Reconnaissance Report</h1>
        <div class="subtitle">Comprehensive Security Analysis</div>
        <div class="meta">
            <div class="meta-item">🎯 Target: <strong>{url}</strong></div>
            <div class="meta-item">📅 Generated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong></div>
            <div class="meta-item">🛠️ Tool: <strong>RECON Dashboard</strong></div>
        </div>
    </div>

    <div class="report-body">
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{len(ports_data.get("open_ports", [])) if isinstance(ports_data, dict) else 0}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="summary-card">
                <div class="number">{subdomain_data.get("total_found", 0) if isinstance(subdomain_data, dict) else 0}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="summary-card">
                <div class="number">{tech_data.get("total_found", 0) if isinstance(tech_data, dict) else 0}</div>
                <div class="label">Technologies</div>
            </div>
            <div class="summary-card">
                <div class="number">{len(crawl_data.get("endpoints", [])) if isinstance(crawl_data, dict) else 0}</div>
                <div class="label">Endpoints</div>
            </div>
            <div class="summary-card">
                <div class="number">{headers_data.get("score", 0) if isinstance(headers_data, dict) else 0}/100</div>
                <div class="label">Security Score</div>
            </div>
            <div class="summary-card">
                <div class="number">{'YES' if isinstance(firewall_data, dict) and (firewall_data.get('cdn_detected') or firewall_data.get('waf_detected') or firewall_data.get('detected')) else 'NO'}</div>
                <div class="label">CDN/WAF Detected</div>
            </div>
        </div>

        {ssl_html}
        {headers_html}
        {ports_html}
        {firewall_html}
        {tech_html}
        {crawl_html}
        {subdomain_html}
        {js_html}
        {screenshot_html}
        {osint_html}
        {threat_html}
        {risk_html}
    </div>

    <div class="report-footer">
        <span>Generated by RECON Dashboard — {url}</span>
        <span>Report for internal use only</span>
    </div>

    <button class="print-btn" onclick="window.print()">🖨️ Print / Save PDF</button>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            var pieCtx = document.getElementById('riskPieChart');
            if (pieCtx) {{
                new Chart(pieCtx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{{
                            data: [{critical_count}, {high_count}, {medium_count}, {low_count}],
                            backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                            borderColor: '#fff',
                            borderWidth: 2
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {{
                            legend: {{
                                position: 'bottom',
                                labels: {{ boxWidth: 10, font: {{ size: 10 }} }}
                            }}
                        }}
                    }}
                }});
            }}
        }});
    </script>
</body>
</html>"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return filepath