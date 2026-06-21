import hashlib
from pathlib import Path
from playwright.async_api import async_playwright
from app.config import SCREENSHOTS_DIR, SCREENSHOT_VIEWPORT
from app.models import ScreenshotResult

def _screenshot_filename(url: str) -> str:
    digest = hashlib.md5(url.encode()).hexdigest()
    return f"{digest}.png"

async def capture_screenshot(url: str) -> ScreenshotResult:
    filename = _screenshot_filename(url)
    output_path: Path = SCREENSHOTS_DIR / filename
    relative_path = f"screenshots/{filename}"

    try:
        # Use a separate playwright instance (not shared)
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
            )
            
            page = await browser.new_page(viewport=SCREENSHOT_VIEWPORT)
            
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                print(f"[Screenshot] Page loaded")
            except:
                try:
                    await page.goto(url, wait_until="commit", timeout=10000)
                    print(f"[Screenshot] Page loaded (partial)")
                except:
                    print(f"[Screenshot] Page load timeout, capturing anyway...")
            
            await page.wait_for_timeout(2000)
            
            try:
                await page.screenshot(path=str(output_path), full_page=False)
                print(f"[Screenshot] ✅ Captured: {filename}")
            except Exception as e:
                print(f"[Screenshot] Screenshot error: {e}")
                await page.screenshot(path=str(output_path), full_page=False, clip={"x": 0, "y": 0, "width": 1280, "height": 800})
                print(f"[Screenshot] ✅ Captured (viewport): {filename}")
            
            await browser.close()
            
        return ScreenshotResult(url=url, screenshot_path=relative_path)
        
    except Exception as exc:
        print(f"[Screenshot] ❌ Error: {exc}")
        return ScreenshotResult(url=url, error=f"Screenshot failed")
