import os
from typing import Dict
from datetime import datetime
from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if url.startswith('https://https://'):
        url = url.replace('https://https://', 'https://')
    elif url.startswith('http://http://'):
        url = url.replace('http://http://', 'http://')
    return url

async def capture_screenshot(url: str) -> Dict:
    """
    ক্যাপচার করে শুধু ভিউপোর্ট (দৃশ্যমান অংশ) – মনিটরের স্ক্রিন সাইজ অনুযায়ী।
    """
    try:
        url = normalize_url(url)
        screenshot_dir = os.path.join('static', 'screenshots')
        os.makedirs(screenshot_dir, exist_ok=True)

        parsed = urlparse(url)
        domain = parsed.hostname or 'unknown'
        filename = f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        filepath = os.path.join(screenshot_dir, filename)

        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                # ভিউপোর্ট সাইজ সেট করুন (যেমন 1280x800)
                page = await browser.new_page(viewport={"width": 1280, "height": 800})
                await page.goto(url, timeout=30000)
                
                # full_page=False দিয়ে শুধু ভিউপোর্ট ক্যাপচার
                await page.screenshot(path=filepath, full_page=False)
                await browser.close()

                return {
                    "screenshot_path": f"screenshots/{filename}",
                    "url": url,
                }

        except ImportError:
            return {
                "error": "Playwright not installed. Run: playwright install",
                "screenshot_path": None,
            }

    except Exception as e:
        print(f"[SCREENSHOT] Error: {e}")
        return {"error": str(e), "screenshot_path": None}