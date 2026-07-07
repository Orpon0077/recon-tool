# ── Automation Scheduler ─────────────────────────────────────
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
import asyncio
from typing import List, Optional, Dict

# ── Global scheduler instance ──
scheduler: Optional[AsyncIOScheduler] = None

# ── Job store ──
_job_store: Dict[str, dict] = {}


def get_scheduler() -> AsyncIOScheduler:
    """Lazy initialization of scheduler with safety checks"""
    global scheduler
    if scheduler is None:
        scheduler = AsyncIOScheduler()
    return scheduler


def schedule_scan(urls: List[str], interval_minutes: int = 60, name: str = None) -> str:
    """
    Schedule automated scans at regular intervals
    """
    sched = get_scheduler()
    job_name = name or f"scan_{datetime.now().strftime('%H%M%S')}"
    
    async def scan_job():
        from app.automation.core import run_automated_scan
        print(f"[SCHEDULER] Starting scheduled job: {job_name} for {len(urls)} URLs")
        for url in urls:
            try:
                await run_automated_scan(url)
            except Exception as e:
                print(f"[SCHEDULER] Error scanning {url} inside job {job_name}: {e}")
    
    job = sched.add_job(
        scan_job,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id=job_name,
        name=job_name,
        replace_existing=True
    )
    
    _job_store[job_name] = {
        "urls": urls,
        "interval": interval_minutes,
        "job_id": job.id,
        "type": "interval"
    }
    
    print(f"[SCHEDULER] ✅ Scheduled: {job_name} (every {interval_minutes} min)")
    return job_name


def schedule_cron_scan(urls: List[str], cron_expr: str, name: str = None) -> str:
    """
    Schedule automated scans using cron expression
    """
    sched = get_scheduler()
    job_name = name or f"cron_{datetime.now().strftime('%H%M%S')}"
    
    async def scan_job():
        from app.automation.core import run_automated_scan
        print(f"[SCHEDULER] Starting scheduled CRON job: {job_name}")
        for url in urls:
            try:
                await run_automated_scan(url)
            except Exception as e:
                print(f"[SCHEDULER] Error scanning {url} inside cron job {job_name}: {e}")
    
    job = sched.add_job(
        scan_job,
        trigger=CronTrigger.from_crontab(cron_expr),
        id=job_name,
        name=job_name,
        replace_existing=True
    )
    
    _job_store[job_name] = {
        "urls": urls,
        "cron": cron_expr,
        "job_id": job.id,
        "type": "cron"
    }
    
    print(f"[SCHEDULER] ✅ Scheduled: {job_name} (cron: {cron_expr})")
    return job_name


def get_scheduled_jobs() -> List[dict]:
    """Get all scheduled jobs cleanly mapped"""
    sched = get_scheduler()
    jobs = []
    for job in sched.get_jobs():
        jobs.append({
            "id": job.id,
            "name": job.name,
            "next_run": str(job.next_run_time) if job.next_run_time else None,
            "trigger": str(job.trigger),
            "pending": getattr(job, 'pending', False)
        })
    return jobs


def remove_job(job_id: str) -> bool:
    """Remove a scheduled job with fail-safety"""
    try:
        sched = get_scheduler()
        sched.remove_job(job_id)
        if job_id in _job_store:
            del _job_store[job_id]
        print(f"[SCHEDULER] ❌ Removed: {job_id}")
        return True
    except Exception as e:
        print(f"[SCHEDULER] Failed to remove {job_id}: {e}")
        return False


def pause_job(job_id: str) -> bool:
    """Pause a scheduled job"""
    try:
        sched = get_scheduler()
        sched.pause_job(job_id)
        print(f"[SCHEDULER] ⏸️ Paused: {job_id}")
        return True
    except Exception as e:
        print(f"[SCHEDULER] Failed to pause {job_id}: {e}")
        return False


def resume_job(job_id: str) -> bool:
    """Resume a paused job"""
    try:
        sched = get_scheduler()
        sched.resume_job(job_id)
        print(f"[SCHEDULER] ▶️ Resumed: {job_id}")
        return True
    except Exception as e:
        print(f"[SCHEDULER] Failed to resume {job_id}: {e}")
        return False


def start_scheduler() -> bool:
    """Start the scheduler safely"""
    sched = get_scheduler()
    if not sched.running:
        sched.start()
        print("[SCHEDULER] 🚀 Started Successfully")
        return True
    print("[SCHEDULER] Scheduler is already running")
    return False


def stop_scheduler() -> bool:
    """Stop the scheduler safely"""
    global scheduler
    if scheduler and scheduler.running:
        scheduler.shutdown()
        scheduler = None
        print("[SCHEDULER] 🛑 Stopped Successfully")
        return True
    print("[SCHEDULER] Scheduler already stopped or uninitialized")
    return False


def get_job_status(job_id: str) -> Optional[dict]:
    """Get status of a specific job"""
    sched = get_scheduler()
    job = sched.get_job(job_id)
    if job:
        return {
            "id": job.id,
            "name": job.name,
            "next_run": str(job.next_run_time) if job.next_run_time else None,
            "trigger": str(job.trigger),
            "pending": getattr(job, 'pending', False)
        }
    return None