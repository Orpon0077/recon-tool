from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import TEMPLATES_DIR, STATIC_DIR, API_TITLE, API_VERSION, API_DESCRIPTION
from app.routers import recon, llm, email, automation
from app.database.db import get_all_scans, get_scan_by_id

# ── No Cache Middleware ──
class NoCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

app = FastAPI(title=API_TITLE, version=API_VERSION, description=API_DESCRIPTION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(NoCacheMiddleware)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ── Include all routers ──
app.include_router(recon)
app.include_router(llm)
app.include_router(email)
app.include_router(automation)

# ── Dashboard ──
@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# ── Chat Page ──
@app.get("/chat", include_in_schema=False)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

# ── Scan History ──
@app.get("/api/history")
async def get_history():
    return await get_all_scans()

@app.get("/api/history/{scan_id}")
async def get_scan(scan_id: str):
    scan = await get_scan_by_id(scan_id)
    if not scan:
        return {"error": "Scan not found"}
    return scan

# ── Health Check ──
@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "version": API_VERSION}