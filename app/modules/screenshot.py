import hashlib
from pathlib import Path
from app.config import SCREENSHOTS_DIR, SCREENSHOT_VIEWPORT
from app.models import ScreenshotResult
from app.modules.playwright_manager import playwright_manager

def _screenshot_filename(url: str) -> str:
    digest = hashlib.md5(url.encode()).hexdigest()
    return f"{digest}.png"

async def capture_screenshot(url: str) -> ScreenshotResult:
    filename = _screenshot_filename(url)
    output_path: Path = SCREENSHOTS_DIR / filename
    relative_path = f"screenshots/{filename}"

    try:
        page = await playwright_manager.new_page()
        
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            print(f"[Screenshot] Page loaded")
        except:
            await page.goto(url, wait_until="commit", timeout=10000)
            print(f"[Screenshot] Page loaded (partial)")
        
        await page.wait_for_timeout(2000)
        await page.screenshot(path=str(output_path), full_page=False)
        await page.close()
        
        print(f"[Screenshot] ✅ Captured: {filename}")
        return ScreenshotResult(url=url, screenshot_path=relative_path)
        
    except Exception as exc:
        print(f"[Screenshot] ❌ Error: {exc}")
        return ScreenshotResult(url=url, error="Screenshot failed")
