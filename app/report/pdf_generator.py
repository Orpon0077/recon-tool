from datetime import datetime
import os


def generate_pdf_report(data: dict, url: str) -> str:
    """
    Professional HTML report generate করে যেটা browser এ দেখা যাবে
    এবং print করে PDF save করা যাবে।
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recon_report_{timestamp}.html"
    filepath = os.path.join("static", "reports", filename)
    os.makedirs(os.path.join("static", "reports"), exist_ok=True)

    # Extract data
    ssl_data = data.get("ssl", {}) or {}
    headers_data = data.get("security_headers", data.get("headers", {})) or {}
    ports_data = data.get("ports", {}) or {}
    firewall_data = data.get("firewall", {}) or {}
    tech_data = data.get("tech", {}) or {}
    crawl_data = data.get("crawl", {}) or {}
    subdomain_data = data.get("subdomains", {}) or {}
    js_data = data.get("js", {}) or {}
    screenshot_data = data.get("screenshot", {}) or {}

    # SSL section
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

    # Security Headers section
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

    # Port Scanning section
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

    # Firewall section
    firewall_html = ""
    if firewall_data and not firewall_data.get("error"):
        detected = firewall_data.get("detected", False)
        fw_name = firewall_data.get("firewall_name", "Unknown")
        evidence = firewall_data.get("evidence", "N/A")
        firewall_html = f"""
        <div class="section">
            <h2>🔥 Firewall / WAF Detection</h2>
            <table>
                <tr><th>Field</th><th>Value</th></tr>
                <tr><td>Detected</td><td style="color:{'#ff4444' if detected else '#00aa55'}; font-weight:bold;">{'YES ⚠️' if detected else 'NO ✓'}</td></tr>
                {'<tr><td>Firewall Name</td><td>' + fw_name + '</td></tr>' if detected else ''}
                <tr><td>Evidence</td><td>{evidence}</td></tr>
            </table>
        </div>
        """
    else:
        firewall_html = f'<div class="section"><h2>🔥 Firewall / WAF Detection</h2><p class="error">Error: {firewall_data.get("error", "No data")}</p></div>'

    # Technology Detection section
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

    # Crawling section
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

    # Subdomain section
    subdomain_html = ""
    if subdomain_data and not subdomain_data.get("error"):
        subdomains = subdomain_data.get("subdomains", [])
        total = subdomain_data.get("total_found", len(subdomains))
        if subdomains:
            sub_rows = "".join([
                f'<tr><td>{s.get("subdomain", "") if isinstance(s, dict) else s}</td><td>{s.get("ip", "N/A") if isinstance(s, dict) else "N/A"}</td></tr>'
                for s in subdomains[:100]
            ])
            subdomain_html = f"""
            <div class="section">
                <h2>🌐 Subdomain Discovery</h2>
                <p>Total subdomains found: <strong>{total}</strong></p>
                <table>
                    <tr><th>Subdomain</th><th>IP Address</th></tr>
                    {sub_rows}
                </table>
            </div>
            """
        else:
            subdomain_html = '<div class="section"><h2>🌐 Subdomain Discovery</h2><p>No subdomains found.</p></div>'
    else:
        subdomain_html = f'<div class="section"><h2>🌐 Subdomain Discovery</h2><p class="error">Error: {subdomain_data.get("error", "No data")}</p></div>'

    # JS Analysis section
    js_html = ""
    if js_data and not js_data.get("error"):
        total_js = js_data.get("total_js_files", js_data.get("total", 0))
        vulnerabilities = js_data.get("vulnerabilities", [])
        emails = js_data.get("emails", [])
        api_endpoints = js_data.get("api_endpoints", [])
        internal_paths = js_data.get("internal_paths", [])

        js_content = f"<p>Total JS files: <strong>{total_js}</strong></p>"
        if emails:
            js_content += f"<p><strong>Emails found:</strong> {', '.join(emails[:10])}</p>"
        if api_endpoints:
            js_content += f"<p><strong>API Endpoints:</strong></p><ul>{''.join(['<li>' + e + '</li>' for e in api_endpoints[:20]])}</ul>"
        if internal_paths:
            js_content += f"<p><strong>Internal Paths:</strong></p><ul>{''.join(['<li>' + p + '</li>' for p in internal_paths[:20]])}</ul>"
        if vulnerabilities:
            vuln_rows = "".join([f'<tr><td>{v.get("file", "")}</td><td style="color:#ff4444;">{v.get("pattern", "")}</td></tr>' for v in vulnerabilities[:20]])
            js_content += f"<p><strong>Potential Issues ({len(vulnerabilities)}):</strong></p><table><tr><th>File</th><th>Pattern</th></tr>{vuln_rows}</table>"

        js_html = f'<div class="section"><h2>📜 JavaScript Analysis</h2>{js_content}</div>'
    else:
        js_html = f'<div class="section"><h2>📜 JavaScript Analysis</h2><p class="error">Error: {js_data.get("error", "No data")}</p></div>'

    # Screenshot section
    screenshot_html = ""
    if screenshot_data and not screenshot_data.get("error"):
        path = screenshot_data.get("screenshot_path", "")
        if path:
            screenshot_html = f"""
            <div class="section">
                <h2>📸 Screenshot</h2>
                <img src="/{path}" alt="Screenshot of {url}" style="max-width:100%; border:1px solid #ddd; border-radius:4px;">
            </div>
            """
        else:
            screenshot_html = '<div class="section"><h2>📸 Screenshot</h2><p>No screenshot available.</p></div>'
    else:
        screenshot_html = f'<div class="section"><h2>📸 Screenshot</h2><p class="error">Error: {screenshot_data.get("error", "No data")}</p></div>'

    # Full HTML report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report — {url}</title>
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
        }}
        .section h2 {{
            font-size: 1.2rem;
            color: #1a1a2e;
            margin-bottom: 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
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
        @media print {{
            .print-btn {{ display: none; }}
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🔍 Web Reconnaissance Report</h1>
        <div class="subtitle">Security Analysis Report</div>
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
                <div class="number">{'YES' if isinstance(firewall_data, dict) and firewall_data.get("detected") else 'NO'}</div>
                <div class="label">WAF Detected</div>
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
    </div>

    <button class="print-btn" onclick="window.print()">🖨️ Print / Save PDF</button>
</body>
</html>"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return filepath