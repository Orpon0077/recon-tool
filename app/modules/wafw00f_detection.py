# ── wafw00f Integration Module ─────────────────────────────
# Uses wafw00f to detect WAF and merge with existing detection

import subprocess
import json
import re
from app.models import FirewallResult

def detect_with_wafw00f(url: str) -> dict:
    """Run wafw00f and parse output"""
    try:
        # Run wafw00f with JSON output
        cmd = f"wafw00f {url} -o /tmp/wafw00f_result.json"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Parse JSON output
        try:
            with open('/tmp/wafw00f_result.json', 'r') as f:
                data = json.load(f)
                return {
                    "detected": True,
                    "firewall_name": data.get('waf', 'Unknown'),
                    "evidence": "wafw00f detection",
                    "source": "wafw00f"
                }
        except:
            # Fallback: parse text output
            output = result.stdout + result.stderr
            
            # Look for WAF name patterns
            patterns = [
                r"The site (.+) is behind (.+)",
                r"WAF Detected: (.+)",
                r"Detected WAF: (.+)",
                r"is behind (.+)",
            ]
            
            for pattern in patterns:
                match = re.search(pattern, output)
                if match:
                    waf_name = match.group(1).strip()
                    if waf_name and waf_name != "None":
                        return {
                            "detected": True,
                            "firewall_name": waf_name,
                            "evidence": "wafw00f detection",
                            "source": "wafw00f"
                        }
            
            return {
                "detected": False,
                "firewall_name": None,
                "evidence": "wafw00f: No WAF detected",
                "source": "wafw00f"
            }
            
    except subprocess.TimeoutExpired:
        print("[wafw00f] Timeout")
        return {"detected": False, "firewall_name": None, "evidence": "wafw00f timeout", "source": "wafw00f"}
    except Exception as e:
        print(f"[wafw00f] Error: {e}")
        return {"detected": False, "firewall_name": None, "evidence": f"wafw00f error: {str(e)[:50]}", "source": "wafw00f"}
