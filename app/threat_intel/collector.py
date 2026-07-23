"""
Threat Intelligence Collection Module
Aggregates reputation data from VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan.
All code is strictly in English.
"""

import asyncio
import aiohttp
import logging
import os
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ThreatIntelCollector:
    """
    Collects threat intelligence for domains and IPs using multiple APIs.
    """

    def __init__(self, domain: str, ips: List[str], subdomains: List[str]):
        self.domain = domain
        self.ips = list(set(ips))
        self.subdomains = list(set(subdomains))
        self.api_keys = {
            "virustotal": os.getenv("VT_API_KEY"),
            "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
            "otx": os.getenv("OTX_API_KEY"),
            "shodan": os.getenv("SHODAN_API_KEY"),
        }
        self.cache: Dict[str, Any] = {}
        self.results: Dict[str, Any] = {}
        self.session: Optional[aiohttp.ClientSession] = None

    async def _fetch_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Fetch VirusTotal IP reputation."""
        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return {"error": "Missing API key"}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}

        try:
            async with self.session.get(url, headers=headers, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    total_vendors = sum(stats.values())
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    return {
                        "detected": malicious > 0,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_vendors": total_vendors,
                        "country": attributes.get("country", "N/A"),
                        "as_owner": attributes.get("as_owner", "N/A"),
                        "reputation": attributes.get("reputation", 0),
                        "source": "VirusTotal",
                    }
                elif resp.status == 429:
                    return {"error": "Rate limited (429)"}
                else:
                    return {"error": f"HTTP {resp.status}"}
        except asyncio.TimeoutError:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    async def _fetch_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Fetch VirusTotal Domain reputation."""
        api_key = self.api_keys.get("virustotal")
        if not api_key:
            return {"error": "Missing API key"}

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}

        try:
            async with self.session.get(url, headers=headers, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)

                    return {
                        "detected": malicious > 0,
                        "malicious_count": malicious,
                        "total_vendors": sum(stats.values()),
                        "reputation": attributes.get("reputation", 0),
                        "source": "VirusTotal",
                    }
                elif resp.status == 429:
                    return {"error": "Rate limited (429)"}
                else:
                    return {"error": f"HTTP {resp.status}"}
        except asyncio.TimeoutError:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    async def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Fetch AbuseIPDB reputation."""
        api_key = self.api_keys.get("abuseipdb")
        if not api_key:
            return {"error": "Missing API key"}

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Key": api_key, "Accept": "application/json"}

        try:
            async with self.session.get(url, params=params, headers=headers, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    data = data.get("data", {})
                    return {
                        "detected": data.get("abuseConfidenceScore", 0) > 0,
                        "abuse_confidence": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country": data.get("countryCode", "N/A"),
                        "isp": data.get("isp", "N/A"),
                        "domain": data.get("domain", "N/A"),
                        "categories": data.get("categories", []),
                        "source": "AbuseIPDB",
                    }
                elif resp.status == 429:
                    return {"error": "Rate limited (429)"}
                else:
                    return {"error": f"HTTP {resp.status}"}
        except asyncio.TimeoutError:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    async def _fetch_otx(self, indicator: str, indicator_type: str = "IPv4") -> Dict[str, Any]:
        """Fetch AlienVault OTX reputation."""
        api_key = self.api_keys.get("otx")
        if not api_key:
            return {"error": "Missing API key"}

        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
        headers = {"X-OTX-API-KEY": api_key}

        try:
            async with self.session.get(url, headers=headers, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulses = data.get("pulse_info", {}).get("pulses", [])
                    return {
                        "detected": len(pulses) > 0,
                        "pulse_count": len(pulses),
                        "reputation": data.get("reputation", 0),
                        "source": "AlienVault OTX",
                    }
                else:
                    return {"error": f"HTTP {resp.status}"}
        except asyncio.TimeoutError:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    async def _fetch_shodan_ip(self, ip: str) -> Dict[str, Any]:
        """Fetch Shodan host data."""
        api_key = self.api_keys.get("shodan")
        if not api_key:
            return {"error": "Missing API key"}

        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            async with self.session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "open_ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "isp": data.get("isp", "N/A"),
                        "org": data.get("org", "N/A"),
                        "os": data.get("os", "N/A"),
                        "hostnames": data.get("hostnames", []),
                        "source": "Shodan",
                    }
                else:
                    return {"error": f"HTTP {resp.status}"}
        except asyncio.TimeoutError:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    def _calculate_risk_score(self, results: Dict[str, Any]) -> int:
        """Calculate a composite risk score (0-100) based on all sources."""
        score = 0

        # VirusTotal
        vt = results.get("virustotal", {})
        if vt.get("detected"):
            score += min(vt.get("malicious_count", 0) * 3, 40)

        # AbuseIPDB
        abuse = results.get("abuseipdb", {})
        if abuse.get("detected"):
            score += min(abuse.get("abuse_confidence", 0) / 2, 30)
            score += min(abuse.get("total_reports", 0) * 2, 20)

        # OTX
        otx = results.get("otx", {})
        if otx.get("detected"):
            score += min(otx.get("pulse_count", 0) * 5, 20)

        return min(score, 100)

    async def _check_entity(self, entity: str, entity_type: str = "ip") -> Dict[str, Any]:
        """Check a single IP or domain against all sources."""
        if entity in self.cache:
            return self.cache[entity]

        result = {}
        if entity_type == "ip":
            # Run all IP checks concurrently
            tasks = [
                self._fetch_virustotal_ip(entity),
                self._fetch_abuseipdb(entity),
                self._fetch_otx(entity, "IPv4"),
                self._fetch_shodan_ip(entity),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            result = {
                "virustotal": results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])},
                "abuseipdb": results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])},
                "otx": results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])},
                "shodan": results[3] if not isinstance(results[3], Exception) else {"error": str(results[3])},
            }
        elif entity_type == "domain":
            # Domain checks (VT Domain, OTX Domain)
            tasks = [
                self._fetch_virustotal_domain(entity),
                self._fetch_otx(entity, "domain"),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            result = {
                "virustotal": results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])},
                "otx": results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])},
            }

        # Calculate score
        score = self._calculate_risk_score(result)
        result["risk_score"] = score
        result["entity"] = entity

        self.cache[entity] = result
        return result

    async def run(self) -> Dict[str, Any]:
        """
        Run threat intelligence collection for main domain and unique IPs.
        """
        logger.info(f"Starting Threat Intelligence collection for {self.domain}")

        async with aiohttp.ClientSession() as session:
            self.session = session

            entities = []

            # 1. Main domain
            entities.append({"entity": self.domain, "type": "domain"})

            # 2. Unique IPs (limit to 20 to avoid rate limits / cost)
            unique_ips = list(set(self.ips))[:20]

            # Filter out invalid IPs (like 'N/A' or empty)
            valid_ips = [ip for ip in unique_ips if ip and ip != "N/A" and "." in ip]
            for ip in valid_ips:
                entities.append({"entity": ip, "type": "ip"})

            # 3. Subdomains (only unique, limit to 10)
            unique_subs = list(set(self.subdomains))[:10]
            for sub in unique_subs:
                if sub and sub != self.domain:  # Avoid duplicating main domain
                    entities.append({"entity": sub, "type": "domain"})

            # Run checks concurrently with a semaphore to respect rate limits
            semaphore = asyncio.Semaphore(5)  # Max 5 concurrent API calls

            async def bounded_check(entity_info):
                async with semaphore:
                    return await self._check_entity(entity_info["entity"], entity_info["type"])

            tasks = [bounded_check(e) for e in entities]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            threat_data = {}
            for i, result in enumerate(results):
                entity = entities[i]["entity"]
                entity_type = entities[i]["type"]
                if isinstance(result, Exception):
                    threat_data[entity] = {"error": str(result)}
                else:
                    threat_data[entity] = result

            # Calculate summary stats
            malicious_ips = []
            high_risk_entities = []

            for entity, data in threat_data.items():
                if isinstance(data, dict):
                    score = data.get("risk_score", 0)
                    if score > 50:
                        high_risk_entities.append(entity)
                    if data.get("virustotal", {}).get("detected") or data.get("abuseipdb", {}).get("detected"):
                        malicious_ips.append(entity)

            return {
                "domain": self.domain,
                "entities_checked": len(threat_data),
                "malicious_entities": malicious_ips,
                "high_risk_entities": high_risk_entities,
                "details": threat_data,
                "summary": {
                    "total_entities": len(threat_data),
                    "malicious_count": len(malicious_ips),
                    "high_risk_count": len(high_risk_entities),
                },
            }