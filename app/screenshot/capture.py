import hashlib
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError
from app.config import SCREENSHOTS_DIR, SCREENSHOT_VIEWPORT
from app.models import ScreenshotResult

def _screenshot_filename(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest() + ".png"

async def capture_screenshot(url: str) -> ScreenshotResult:
    filename = _screenshot_filename(url)
    output_path = SCREENSHOTS_DIR / filename
    relative_path = f"screenshots/{filename}"

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-setuid-sandbox',
                    '--no-first-run',
                    '--no-zygote',
                    '--single-process'
                ]
            )
            
            page = await browser.new_page(
                viewport=SCREENSHOT_VIEWPORT,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            
            # ── Try different strategies ──
            strategies = [
                {"wait_until": "domcontentloaded", "timeout": 30000},
                {"wait_until": "commit", "timeout": 20000},
                {"wait_until": "load", "timeout": 15000},
                {"wait_until": "networkidle", "timeout": 10000},
            ]
            
            loaded = False
            for strategy in strategies:
                try:
                    await page.goto(url, wait_until=strategy["wait_until"], timeout=strategy["timeout"])
                    print(f"[Screenshot] ✅ Loaded: {strategy['wait_until']} ({strategy['timeout']}ms)")
                    loaded = True
                    break
                except PWTimeoutError:
                    print(f"[Screenshot] ⚠️ Timeout: {strategy['wait_until']}")
                    continue
            
            # ── If all strategies failed, try direct navigation ──
            if not loaded:
                try:
                    await page.goto(url, timeout=5000)
                    print(f"[Screenshot] ✅ Loaded: direct")
                    loaded = True
                except:
                    print(f"[Screenshot] ⚠️ Direct navigation failed")
            
            # ── Wait for rendering ──
            await page.wait_for_timeout(2000)
            
            # ── Take screenshot ──
            try:
                await page.screenshot(path=str(output_path), full_page=False, timeout=15000)
                print(f"[Screenshot] ✅ Captured: {filename}")
            except Exception as e:
                print(f"[Screenshot] ⚠️ Screenshot error: {e}")
                # Try fallback: viewport only
                await page.screenshot(
                    path=str(output_path),
                    full_page=False,
                    clip={"x": 0, "y": 0, "width": 1280, "height": 800}
                )
                print(f"[Screenshot] ✅ Captured (viewport): {filename}")
            
            await browser.close()
            
        return ScreenshotResult(url=url, screenshot_path=relative_path)
        
    except Exception as e:
        print(f"[Screenshot] ❌ Error: {e}")
        return ScreenshotResult(url=url, error=f"Screenshot failed: {str(e)[:100]}")
