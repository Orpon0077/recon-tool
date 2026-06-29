from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pathlib import Path

router = APIRouter(prefix="/api/llm", tags=["llm"])
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def chat_ui(request: Request):
    """Serve the chat HTML page"""
    return templates.TemplateResponse("chat.html", {"request": request})

# ── Re-import all chat functionality ──
from app.llm.router import router as chat_router
router.include_router(chat_router)
