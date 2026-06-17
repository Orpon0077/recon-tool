import hashlib
from pathlib import Path
from playwright.async_api import async_playwright
from app.config import SCREENSHOTS_DIR, SCREENSHOT_VIEWPORT, SCREENSHOT_TIMEOUT_MS
from app.models import ScreenshotResult

def _screenshot_filename(url: str) -> str:
    digest = hashlib.md5(url.encode()).hexdigest()
    return f"{digest}.png"

async def capture_screenshot(url: str) -> ScreenshotResult:
    filename = _screenshot_filename(url)
    output_path: Path = SCREENSHOTS_DIR / filename
    relative_path = f"screenshots/{filename}"

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1280, "height": 800})
            
            # Try networkidle first, fallback to domcontentloaded
            try:
                await page.goto(url, wait_until="networkidle", timeout=60000)
            except:
                await page.goto(url, wait_until="domcontentloaded", timeout=60000)
            
            await page.wait_for_timeout(3000)
            await page.screenshot(path=str(output_path), full_page=False)
            await browser.close()
            
        return ScreenshotResult(url=url, screenshot_path=relative_path)
        
    except Exception as exc:
        print(f"[Screenshot] Error: {exc}")
        return ScreenshotResult(url=url, error=str(exc))
