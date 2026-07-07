# ── LLM Tools Definition ──
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scan_website",
            "description": "Full website scan - all modules: SSL, security headers, ports, subdomains, technologies, crawl, JS",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to scan"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_ssl",
            "description": "SSL/TLS certificate analysis only",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to analyze"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_security",
            "description": "Security headers analysis only",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to analyze"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_ports",
            "description": "Port scanning only",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to scan"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_subdomains",
            "description": "Subdomain discovery only",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to discover subdomains for"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_tech",
            "description": "Technology detection only",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to detect technologies for"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_crawl",
            "description": "Crawl endpoints only",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to crawl"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_js",
            "description": "JavaScript scanner only",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to scan JS files for"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_pdf",
            "description": "Generate a PDF report of the most recent scan results for a domain. If no scan exists, it will run a full scan first automatically.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain to generate report for (e.g., example.com)"}
                },
                "required": ["domain"]
            }
        }
    }
]