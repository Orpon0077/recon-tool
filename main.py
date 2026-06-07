from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from app.config import TEMPLATES_DIR, STATIC_DIR, API_TITLE, API_VERSION, API_DESCRIPTION
from app.routers import recon_router

app = FastAPI(title=API_TITLE, version=API_VERSION, description=API_DESCRIPTION)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.include_router(recon_router)


@app.get("/", include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "version": API_VERSION}
