def format_with_reasoning(action: str, result: dict, reasoning: str) -> str:
    response = f"ACTION: {action}\n"
    response += f"REASONING: {reasoning}\n\n"
    response += f"RESULT:\n"
    
    for key, value in result.items():
        if isinstance(value, dict):
            response += f"- {key}:\n"
            for k, v in value.items():
                # ── SSL Details ──
                if k == 'ssl' and isinstance(v, dict):
                    response += f"    - SSL Certificate:\n"
                    response += f"        - Issued To: {v.get('issued_to', 'N/A')}\n"
                    response += f"        - Issued By: {v.get('issued_by', 'N/A')}\n"
                    response += f"        - Valid From: {v.get('valid_from', 'N/A')}\n"
                    response += f"        - Valid Until: {v.get('valid_until', 'N/A')}\n"
                    response += f"        - Days Remaining: {v.get('days_remaining', 'N/A')}\n"
                    response += f"        - Expired: {v.get('is_expired', 'N/A')}\n"
                
                # ── Security Headers Details ──
                elif k == 'security_headers' and isinstance(v, dict):
                    response += f"    - Security Headers:\n"
                    response += f"        - Score: {v.get('score', 0)}/100\n"
                    present = v.get('present', {})
                    if present:
                        response += f"        - Present Headers:\n"
                        for header, value in present.items():
                            response += f"            ✓ {header}: {value}\n"
                    missing = v.get('missing', [])
                    if missing:
                        response += f"        - Missing Headers:\n"
                        for header in missing:
                            response += f"            ✗ {header}\n"
                
                # ── Port Scan Details ──
                elif k == 'ports' and isinstance(v, dict):
                    response += f"    - Port Scan:\n"
                    response += f"        - Host: {v.get('host', 'N/A')}\n"
                    response += f"        - Open Ports: {v.get('total_open', 0)}\n"
                    open_ports = v.get('open_ports', [])
                    if open_ports:
                        for port in open_ports:
                            if isinstance(port, dict):
                                response += f"            - Port {port.get('port', 'N/A')}: {port.get('service', 'unknown')} ({port.get('state', 'unknown')})\n"
                            else:
                                response += f"            - {port}\n"
                
                # ── Screenshot Details ──
                elif k == 'screenshot' and isinstance(v, dict):
                    response += f"    - Screenshot:\n"
                    response += f"        - Path: {v.get('screenshot_path', 'N/A')}\n"
                    if v.get('screenshot_path'):
                        response += f"        - View: http://localhost:8000/static/{v.get('screenshot_path')}\n"
                
                # ── Firewall Details ──
                elif k == 'firewall' and isinstance(v, dict):
                    response += f"    - Firewall Detection:\n"
                    if v.get('detected'):
                        response += f"        - Status: DETECTED\n"
                        response += f"        - Firewall: {v.get('firewall_name', 'Unknown')}\n"
                        response += f"        - Evidence: {v.get('evidence', 'N/A')}\n"
                    else:
                        response += f"        - Status: NOT DETECTED\n"
                        response += f"        - Evidence: {v.get('evidence', 'No WAF detected')}\n"
                
                # ── Tech Detection Details ──
                elif k == 'tech' and isinstance(v, dict):
                    response += f"    - Technology Detection:\n"
                    response += f"        - Total: {v.get('total_found', 0)} technologies\n"
                    technologies = v.get('technologies', {})
                    if technologies:
                        for category, techs in technologies.items():
                            if isinstance(techs, list):
                                response += f"        - {category}: {', '.join(techs)}\n"
                            else:
                                response += f"        - {category}: {techs}\n"
                
                # ── Crawl Details ──
                elif k == 'crawl' and isinstance(v, dict):
                    response += f"    - Crawl Results:\n"
                    response += f"        - Total Endpoints: {v.get('total_found', 0)}\n"
                    endpoints = v.get('endpoints', [])
                    if endpoints:
                        response += f"        - Endpoints:\n"
                        for i, endpoint in enumerate(endpoints[:30], 1):
                            if isinstance(endpoint, dict):
                                url = endpoint.get('url', 'N/A')
                                status = endpoint.get('status_code', 'N/A')
                                method = endpoint.get('method', 'GET')
                                content_type = endpoint.get('content_type', '')
                                response += f"            {i}. {method} {url} (Status: {status})"
                                if content_type:
                                    response += f" [{content_type}]"
                                response += "\n"
                        if len(endpoints) > 30:
                            response += f"            ... and {len(endpoints) - 30} more endpoints\n"
                
                # ── JS Scanner Details ──
                elif k == 'js_scanner' and isinstance(v, dict):
                    response += f"    - JavaScript Scanner:\n"
                    response += f"        - Total JS Files: {v.get('total_js_files', 0)}\n"
                    js_files = v.get('js_files', [])
                    if js_files:
                        response += f"        - JS Files:\n"
                        for i, js in enumerate(js_files[:15], 1):
                            if isinstance(js, dict):
                                name = js.get('name', js.get('url', 'N/A'))
                                response += f"            {i}. {name}\n"
                            else:
                                response += f"            {i}. {js}\n"
                        if len(js_files) > 15:
                            response += f"            ... and {len(js_files) - 15} more files\n"
                    
                    emails = v.get('emails', [])
                    if emails:
                        response += f"        - Emails Found:\n"
                        for email in emails[:10]:
                            response += f"            - {email}\n"
                    
                    internal_paths = v.get('internal_paths', [])
                    if internal_paths:
                        response += f"        - Internal Paths:\n"
                        for path in internal_paths[:15]:
                            response += f"            - {path}\n"
                
                # ── Subdomain Details ──
                elif k == 'subdomains' and isinstance(v, dict):
                    response += f"    - Subdomain Discovery:\n"
                    response += f"        - Total: {v.get('total_found', 0)}\n"
                    subdomains = v.get('subdomains', [])
                    if subdomains:
                        response += f"        - Subdomains:\n"
                        for i, sub in enumerate(subdomains[:20], 1):
                            if isinstance(sub, dict):
                                sub_name = sub.get('subdomain', sub.get('name', 'N/A'))
                                ip = sub.get('ip', 'N/A')
                                response += f"            {i}. {sub_name} -> {ip}\n"
                            else:
                                response += f"            {i}. {sub}\n"
                        if len(subdomains) > 20:
                            response += f"            ... and {len(subdomains) - 20} more subdomains\n"
                
                # ── Default for other fields ──
                else:
                    response += f"    - {k}: {v}\n"
        
        elif isinstance(value, list):
            response += f"- {key}: {len(value)} items\n"
            for i, item in enumerate(value[:10], 1):
                if isinstance(item, dict):
                    response += f"    {i}. {item}\n"
                else:
                    response += f"    {i}. {item}\n"
            if len(value) > 10:
                response += f"    ... and {len(value) - 10} more items\n"
        else:
            response += f"- {key}: {value}\n"
    
    return response

def get_reasoning(intent: str, url: str) -> str:
    reasoning_map = {
        "full": f"I am performing a comprehensive reconnaissance scan on {url} to gather all available security and infrastructure information.",
        "firewall": f"I am checking for WAF/Firewall protection on {url} to identify any security layers.",
        "ssl": f"I am analyzing the SSL/TLS certificate for {url} to check its validity and security.",
        "security": f"I am checking security headers for {url} to evaluate its security posture.",
        "ports": f"I am scanning open ports on {url} to identify running services.",
        "subdomains": f"I am discovering subdomains for {url} to map the attack surface.",
        "tech": f"I am detecting technologies used on {url} to understand the tech stack.",
        "crawl": f"I am crawling {url} to discover all accessible endpoints.",
        "js": f"I am analyzing JavaScript files on {url} to find sensitive information.",
        "screenshot": f"I am capturing a screenshot of {url} for visual reference.",
        "ask": f"I am asking the user what they want to scan on {url}."
    }
    return reasoning_map.get(intent, f"I am processing your request for {url}.")
