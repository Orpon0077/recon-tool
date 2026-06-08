# ── Screenshot Module ──────────────────────────────────────
# Website এর homepage এর screenshot নেয়

import hashlib
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeout
from app.config import SCREENSHOTS_DIR, SCREENSHOT_VIEWPORT, SCREENSHOT_TIMEOUT_MS
from app.models import ScreenshotResult


def _screenshot_filename(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest() + ".png"


async def capture_screenshot(url: str) -> ScreenshotResult:
    filename = _screenshot_filename(url)
    output_path = SCREENSHOTS_DIR / filename
    relative_path = f"screenshots/{filename}"

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport=SCREENSHOT_VIEWPORT,
                ignore_https_errors=True,
            )
            page = await context.new_page()

            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=SCREENSHOT_TIMEOUT_MS,
            )

            try:
                await page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass

            await page.wait_for_timeout(10000)
            await page.evaluate("window.scrollTo(0, 0)")
            await page.wait_for_timeout(1000)
            await page.screenshot(path=str(output_path), full_page=False)
            await browser.close()

        return ScreenshotResult(url=url, screenshot_path=relative_path)

    except PWTimeout:
        return ScreenshotResult(url=url, error="Page load timed out")
    except Exception as e:
        return ScreenshotResult(url=url, error=str(e))