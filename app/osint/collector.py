"""
Open Source Intelligence (OSINT) Collection Module
All code is strictly in English.
DNS lookup is disabled to avoid import issues.
"""

import asyncio
import logging
from typing import Dict, List, Any

import aiohttp
import whois

logger = logging.getLogger(__name__)


class OSINTCollector:
    """
    Collects OSINT data for a given domain using public APIs and libraries.
    DNS collection is skipped to avoid dependency problems.
    """

    def __init__(self, domain: str):
        self.domain = domain.strip().lower()

    def get_whois(self) -> Dict[str, Any]:
        try:
            w = whois.whois(self.domain)
            return {
                "registrar": str(w.registrar) if w.registrar else None,
                "creation_date": str(w.creation_date[0]) if isinstance(w.creation_date, list) and w.creation_date else str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date[0]) if isinstance(w.expiration_date, list) and w.expiration_date else str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
            }
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {self.domain}: {e}")
            return {"error": str(e)}

    async def get_wayback_urls(self, limit: int = 100, retries: int = 3) -> List[str]:
        """
        Fetch historical URLs from the Wayback Machine CDX API.
        Includes delay and retry mechanism to avoid rate limiting.
        """
        url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=original&limit={limit}&collapse=urlkey"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (compatible; ReconTool/1.0)"
        }

        for attempt in range(retries + 1):
            try:
                # ── Delay to avoid rate limiting ──
                await asyncio.sleep(1.5 * (attempt + 1))

                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data and len(data) > 1:
                                raw_urls = data[1:]
                                return list(set([str(u) for u in raw_urls if isinstance(u, str)]))
                        elif resp.status == 429:
                            await asyncio.sleep(5)
                            continue
                        return []
            except asyncio.TimeoutError:
                if attempt < retries:
                    await asyncio.sleep(2)
                    continue
                logger.debug(f"Wayback Machine timeout for {self.domain}")
                return []
            except Exception as e:
                if attempt < retries:
                    await asyncio.sleep(2)
                    continue
                logger.debug(f"Wayback Machine failed for {self.domain}: {e}")
                return []
        return []

    async def get_crt_sh_subdomains(self) -> List[str]:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        subdomains = set()
                        for entry in data:
                            name = entry.get("name_value", "")
                            if name:
                                for part in name.split("\n"):
                                    clean = part.strip().lower()
                                    if clean and clean.endswith(self.domain):
                                        subdomains.add(clean)
                        return [str(s) for s in subdomains if isinstance(s, str)]
                    return []
        except Exception as e:
            logger.debug(f"crt.sh fetch failed for {self.domain}: {e}")
            return []

    async def run_all(self) -> Dict[str, Any]:
        logger.info(f"Starting OSINT collection for {self.domain}")
        whois_data = self.get_whois()
        wayback_data = await self.get_wayback_urls()
        crt_data = await self.get_crt_sh_subdomains()

        return {
            "whois": whois_data,
            "dns_records": {},
            "wayback_urls": wayback_data,
            "crt_subdomains": crt_data,
            "total_subdomains_found_osint": len(set(crt_data)),
        }