from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from app.automation.core import run_automated_scan, send_scan_report
from app.automation.scheduler import get_scheduled_jobs, start_scheduler, get_scheduler

router = APIRouter(prefix="/api/automation", tags=["automation"])

class ScanRequest(BaseModel):
    urls: List[str]
    notify: bool = True


def ensure_scheduler():
    """State-aware checker instead of dummy boolean flag"""
    sched = get_scheduler()
    if not sched.running:
        start_scheduler()


async def background_scan_worker(urls: List[str], notify: bool):
    """Asynchronous worker to process heavy scans out of request thread"""
    for url in urls:
        try:
            result = await run_automated_scan(url)
            if notify and result.get("success"):
                await send_scan_report(url, result.get("result", {}))
        except Exception as e:
            print(f"[BACKGROUND SCAN] Critical error processing {url}: {e}")


@router.post("/scan")
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Trigger non-blocking instant scan for one or more URLs"""
    ensure_scheduler()
    
    if not request.urls:
        raise HTTPException(status_code=400, detail="Target URL list cannot be empty.")
    
    # Push scanning to framework native background tasks to keep API ultra-responsive
    background_tasks.add_task(background_scan_worker, request.urls, request.notify)
    
    return {
        "status": "processing",
        "message": f"Scan initiated in background for {len(request.urls)} targets.",
        "targets": request.urls,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/status")
async def get_automation_status():
    """Get automation system status along with metrics"""
    ensure_scheduler()
    sched = get_scheduler()
    jobs = get_scheduled_jobs()
    return {
        "status": "running" if sched.running else "stopped",
        "total_jobs": len(jobs),
        "jobs": jobs,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/jobs")
async def get_jobs():
    """Get all current scheduled jobs inside memory"""
    ensure_scheduler()
    jobs = get_scheduled_jobs()
    return {
        "total": len(jobs),
        "jobs": jobs,
        "timestamp": datetime.now().isoformat()
    }