# ── LLM Tool Definitions ──────────────────────────────────
# এই Tools গুলো AI call করতে পারবে

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scan_website",
            "description": "Scan a website for security, technology, subdomains, ports, and vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL of the website to scan (e.g., example.com)"
                    }
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_history",
            "description": "Get history of all previous scans",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of scans to return (default: 20)"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "export_pdf_report",
            "description": "Generate PDF report of scan results",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL that was scanned"
                    }
                },
                "required": ["url"]
            }
        }
    }
]
