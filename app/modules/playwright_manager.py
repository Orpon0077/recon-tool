# ── Playwright Singleton Manager ──────────────────────────
import asyncio
from playwright.async_api import async_playwright, Browser, Playwright

class PlaywrightManager:
    _instance = None
    _playwright: Playwright = None
    _browser: Browser = None
    _lock = asyncio.Lock()
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PlaywrightManager, cls).__new__(cls)
        return cls._instance
    
    async def get_browser(self) -> Browser:
        """Get or create a single browser instance"""
        async with self._lock:
            if not self._initialized:
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
                )
                self._initialized = True
                print("[Playwright] Browser initialized")
            return self._browser
    
    async def new_page(self):
        """Create a new page from shared browser"""
        browser = await self.get_browser()
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=True
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
            self._initialized = False
            print("[Playwright] Browser closed")

# Global instance
playwright_manager = PlaywrightManager()
