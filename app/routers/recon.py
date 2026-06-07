import asyncio
from fastapi import APIRouter
from app.models import ScanRequest, SSLResult
from app.modules import analyze_ssl

router = APIRouter(prefix="/api", tags=["recon"])

@router.post("/ssl", response_model=SSLResult)
async def api_ssl(payload: ScanRequest):
    return await asyncio. to_thread(analyze_ssl, payload.url)
