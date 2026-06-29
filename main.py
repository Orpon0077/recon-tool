# ── Main Application ───────────────────────────────────────
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from app.config import TEMPLATES_DIR, STATIC_DIR, API_TITLE, API_VERSION, API_DESCRIPTION
from app.routers import recon_router
from app.routers.automation import router as automation_router
from app.routers.email import router as email_router
from app.database.db import get_all_scans, get_scan_by_id

app = FastAPI(title=API_TITLE, version=API_VERSION, description=API_DESCRIPTION)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app.include_router(recon_router)
app.include_router(automation_router)
app.include_router(email_router)

# ── Dashboard UI ──
@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# ── AI Chat UI (Direct route - must be before LLM router) ──
@app.get("/chat", include_in_schema=False)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

# ── LLM API Router ──
from app.llm.router import router as llm_router
app.include_router(llm_router)

# ── Scan History ──
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

# ── Scheduler ──
@app.on_event("startup")
async def startup_event():
    from app.automation.scheduler import scheduler
    scheduler.start()
    print("🚀 Scheduler started!")

@app.on_event("shutdown")
async def shutdown_event():
    from app.automation.scheduler import scheduler
    scheduler.stop()
    print("🛑 Scheduler stopped!")

# ── Health Check ──
@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "version": API_VERSION}
