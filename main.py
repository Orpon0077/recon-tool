from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from app.config import TEMPLATES_DIR, STATIC_DIR, API_TITLE, API_VERSION, API_DESCRIPTION
from app.routers import recon
from app.routers import llm
from app.database import get_all_scans, get_scan_by_id

app = FastAPI(title=API_TITLE, version=API_VERSION, description=API_DESCRIPTION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app.include_router(recon.router)
app.include_router(llm.router)

@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/chat", include_in_schema=False)
async def chat_page(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request})

@app.get("/api/history")
async def get_history():
    return await get_all_scans()

@app.get("/api/history/{scan_id}")
async def get_scan(scan_id: str):
    return await get_scan_by_id(scan_id)

@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "version": API_VERSION}
