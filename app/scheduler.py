# ── Task Scheduler ──────────────────────────────────────────
# Handles scheduled scans and automation

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import asyncio
import logging

logger = logging.getLogger(__name__)

class ScanScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.jobs = {}
        self._setup_default_jobs()
    
    def _setup_default_jobs(self):
        """Setup default scheduled jobs"""
        
        # ── Daily scan at 6 AM ──
        self.scheduler.add_job(
            func=self._daily_scan,
            trigger=CronTrigger(hour=6, minute=0),
            id='daily_scan',
            name='Daily Security Scan',
            replace_existing=True
        )
        logger.info("✅ Daily scan scheduled at 6:00 AM")
        
        # ── Weekly full scan on Monday 7 AM ──
        self.scheduler.add_job(
            func=self._weekly_scan,
            trigger=CronTrigger(day_of_week='mon', hour=7, minute=0),
            id='weekly_scan',
            name='Weekly Full Scan',
            replace_existing=True
        )
        logger.info("✅ Weekly scan scheduled on Monday 7:00 AM")
        
        # ── Status check every hour ──
        self.scheduler.add_job(
            func=self._status_check,
            trigger=IntervalTrigger(hours=1),
            id='status_check',
            name='Status Check',
            replace_existing=True
        )
        logger.info("✅ Status check scheduled every hour")
    
    def _daily_scan(self):
        """Daily scan job"""
        logger.info(f"[{datetime.now()}] Running daily scan...")
        asyncio.run(self._run_scan("daily"))
    
    def _weekly_scan(self):
        """Weekly full scan job"""
        logger.info(f"[{datetime.now()}] Running weekly full scan...")
        asyncio.run(self._run_scan("weekly"))
    
    def _status_check(self):
        """Status check job"""
        logger.info(f"[{datetime.now()}] Status check completed")
    
    async def _run_scan(self, scan_type: str):
        """Run automated scan"""
        try:
            from app.automation import run_automated_scan, send_scan_report
            
            # Get URLs to scan
            urls = await self._get_target_urls(scan_type)
            
            for url in urls:
                logger.info(f"[{datetime.now()}] Scanning: {url}")
                result = await run_automated_scan(url)
                
                if result.get('success'):
                    # Send notification
                    await send_scan_report(url, result)
                    
        except Exception as e:
            logger.error(f"Scan error: {e}")
    
    async def _get_target_urls(self, scan_type: str) -> list:
        """Get URLs to scan based on type"""
        # Default URLs - you can change these
        urls = ['axiler.com', 'polysignals.app']
        return urls
    
    def start(self):
        """Start the scheduler"""
        self.scheduler.start()
        logger.info("🚀 Scheduler started!")
    
    def stop(self):
        """Stop the scheduler"""
        self.scheduler.shutdown()
        logger.info("🛑 Scheduler stopped!")
    
    def add_job(self, name: str, func, trigger, **kwargs):
        """Add custom job"""
        job_id = f"custom_{name}_{datetime.now().timestamp()}"
        self.scheduler.add_job(
            func=func,
            trigger=trigger,
            id=job_id,
            name=name,
            replace_existing=True,
            **kwargs
        )
        logger.info(f"✅ Added job: {name}")
        return job_id
    
    def remove_job(self, job_id: str):
        """Remove a job"""
        self.scheduler.remove_job(job_id)
        logger.info(f"✅ Removed job: {job_id}")
    
    def get_jobs(self):
        """Get all jobs"""
        return self.scheduler.get_jobs()

# ── Global scheduler instance ──
scheduler = ScanScheduler()
