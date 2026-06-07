from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR/"templates"
STATIC_DIR = BASE_DIR/"static"
SCREENSHOTS_DIR = BASE_DIR/"static"/"screenshots"

SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

REQUEST_TIMEOUT = 10
REQUEST_HEADER = {
     "User-Agent": (
         "Mozila/5.0 (X11; Linux x86_64)"
         "AppleWebKit/537.36 (KHTML, like Gecko)"
         "Chrome/124.0.0.0 Safari/537.36"
         )
}
SCREENSHOT_VIEWPORT = {"width":1280, "height": 800}
SCREENSHOT_TIMEOUT_MS = 30_000

API_TITLE = "Recon Tool"
API_VERSION = "1.0.0"
API_DESCRIPTION = "Web Reconnaissance Tool"
