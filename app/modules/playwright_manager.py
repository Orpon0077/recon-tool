# ── Playwright Singleton Manager ──────────────────────────
# Prevents "Racing with another loop" errors by reusing one Playwright instance

import asyncio
from playwright.async_api import async_playwright, Playwright, Browser, BrowserContext, Page

class PlaywrightManager:
    _instance = None
    _playwright = None
    _browser = None
    _lock = asyncio.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PlaywrightManager, cls).__new__(cls)
        return cls._instance
    
    async def get_browser(self) -> Browser:
        """Get or create a single browser instance"""
        async with self._lock:
            if self._playwright is None:
                self._playwright = await async_playwright().start()
            
            if self._browser is None or not self._browser.is_connected():
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
                )
            return self._browser
    
    async def new_page(self) -> Page:
        """Create a new page from the shared browser"""
        browser = await self.get_browser()
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        return await context.new_page()
    
    async def close(self):
        """Clean up resources"""
        async with self._lock:
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None

# Global instance
playwright_manager = PlaywrightManager()

async def cleanup_playwright():
    """Call this on shutdown"""
    await playwright_manager.close()
