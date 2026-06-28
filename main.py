# ── Main Application ───────────────────────────────────────
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from app.config import TEMPLATES_DIR, STATIC_DIR, API_TITLE, API_VERSION, API_DESCRIPTION
from app.routers import recon_router, llm_router
from app.database import get_all_scans, get_scan_by_id

app = FastAPI(title=API_TITLE, version=API_VERSION, description=API_DESCRIPTION)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.include_router(recon_router)
app.include_router(llm_router)


# ── Dashboard UI ───────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ── AI Chat UI ─────────────────────────────────────────────
@app.get("/chat", include_in_schema=False)
async def chat_ui(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})


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


# ── Health Check ───────────────────────────────────────────
@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "version": API_VERSION}

# ── Shutdown Cleanup ──
@app.on_event("shutdown")
async def shutdown_event():
    from app.modules.playwright_manager import playwright_manager
    await playwright_manager.close()
    print("[Shutdown] Playwright cleaned up")

# ── Automation Router ──
from app.routers.automation import router as automation_router
app.include_router(automation_router)

# ── Start Scheduler on startup ──
@app.on_event("startup")
async def startup_event():
    from app.scheduler import scheduler
    scheduler.start()
    print("🚀 Scheduler started!")

# ── Stop Scheduler on shutdown ──
@app.on_event("shutdown")
async def shutdown_event():
    from app.scheduler import scheduler
    scheduler.stop()
    print("🛑 Scheduler stopped!")
