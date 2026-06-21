# ── Screenshot Module (Independent & Reliable) ────────────
import hashlib
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError
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
        # ── Launch browser with clean context ──
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-setuid-sandbox',
                    '--disable-accelerated-2d-canvas',
                    '--disable-pdf-viewer',
                ]
            )
            
            # ── Create context ──
            context = await browser.new_context(
                viewport=SCREENSHOT_VIEWPORT,
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                java_script_enabled=True,
                bypass_csp=True,
            )
            
            page = await context.new_page()
            
            # ── Set default timeout ──
            page.set_default_timeout(15000)
            
            # ── Try to load the page ──
            try:
                # Strategy 1: domcontentloaded (fastest)
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                print(f"[Screenshot] ✅ Page loaded (domcontentloaded)")
            except PWTimeoutError:
                try:
                    # Strategy 2: commit (just HTML)
                    await page.goto(url, wait_until="commit", timeout=8000)
                    print(f"[Screenshot] ✅ Page loaded (commit)")
                except PWTimeoutError:
                    # Strategy 3: Try with shorter timeout
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=5000)
                        print(f"[Screenshot] ✅ Page loaded (fast)")
                    except:
                        print(f"[Screenshot] ⚠️ Page partially loaded, capturing anyway...")
            
            # ── Wait for rendering ──
            await asyncio.sleep(2)
            
            # ── Capture screenshot ──
            try:
                await page.screenshot(
                    path=str(output_path),
                    full_page=False,
                    type='png',
                    timeout=10000
                )
                print(f"[Screenshot] ✅ Captured: {filename}")
            except Exception as e:
                print(f"[Screenshot] ⚠️ Screenshot error: {e}")
                # Try fallback: viewport only
                try:
                    await page.screenshot(
                        path=str(output_path),
                        full_page=False,
                        type='png'
                    )
                    print(f"[Screenshot] ✅ Captured (viewport fallback): {filename}")
                except:
                    raise
            
            # ── Clean up ──
            await page.close()
            await context.close()
            await browser.close()
            
        return ScreenshotResult(url=url, screenshot_path=relative_path)
        
    except asyncio.TimeoutError:
        print(f"[Screenshot] ❌ Timeout error for {url}")
        return ScreenshotResult(url=url, error="Screenshot timeout - page took too long to load")
        
    except Exception as exc:
        print(f"[Screenshot] ❌ Error: {exc}")
        # Return partial screenshot if possible
        try:
            if 'output_path' in locals() and output_path.exists():
                return ScreenshotResult(url=url, screenshot_path=relative_path)
        except:
            pass
        return ScreenshotResult(url=url, error=f"Screenshot failed: {str(exc)[:100]}")
