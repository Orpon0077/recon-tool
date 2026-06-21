# ── Main Application ───────────────────────────────────────
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from app.config import TEMPLATES_DIR, STATIC_DIR, API_TITLE, API_VERSION, API_DESCRIPTION
from app.routers import recon_router
from app.database import get_all_scans, get_scan_by_id
from app.modules import cleanup_playwright

app = FastAPI(title=API_TITLE, version=API_VERSION, description=API_DESCRIPTION)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.include_router(recon_router)


# ── Dashboard UI ───────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ── Scan History ───────────────────────────────────────────
@app.get("/api/history")
async def get_history():
    scans = await get_all_scans()
    return scans


@app.get("/api/history/{scan_id}")
async def get_scan(scan_id: str):
    scan = await get_scan_by_id(scan_id)
    if not scan:
        return {"error": "Scan not found"}
    return scan


# ── Shutdown Cleanup ──────────────────────────────────────
@app.on_event("shutdown")
async def shutdown_event():
    await cleanup_playwright()
    print("[Shutdown] Playwright cleaned up")


# ── Health Check ───────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "version": API_VERSION}
