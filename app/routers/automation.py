# ── Automation Router ──────────────────────────────────────
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from app.automation import run_automated_scan, send_scan_report
from app.scheduler import scheduler

router = APIRouter(prefix="/api/automation", tags=["automation"])

class ScanRequest(BaseModel):
    urls: List[str]
    notify: bool = True

@router.post("/scan")
async def trigger_scan(request: ScanRequest):
    """Trigger an automated scan"""
    results = []
    
    for url in request.urls:
        result = await run_automated_scan(url)
        results.append({
            "url": url,
            "success": result.get("success", False),
            "scan_id": result.get("scan_id"),
            "error": result.get("error")
        })
        
        if request.notify and result.get("success"):
            await send_scan_report(url, result)
    
    return {
        "total": len(results),
        "success": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "results": results
    }

@router.get("/jobs")
async def get_jobs():
    """Get all scheduled jobs with next run time"""
    jobs = scheduler.get_jobs()
    return {
        "jobs": [
            {
                "id": job.id,
                "name": job.name,
                "trigger": str(job.trigger),
                "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None
            }
            for job in jobs
        ]
    }

@router.get("/status")
async def get_automation_status():
    """Get automation system status"""
    jobs = scheduler.get_jobs()
    return {
        "status": "running",
        "total_jobs": len(jobs),
        "jobs": [
            {
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None
            }
            for job in jobs
        ]
    }
