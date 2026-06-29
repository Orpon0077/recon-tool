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
        self._setup_default_jobs()
    
    def _setup_default_jobs(self):
        self.scheduler.add_job(
            func=self._daily_scan,
            trigger=CronTrigger(hour=6, minute=0),
            id='daily_scan',
            name='Daily Security Scan',
            replace_existing=True
        )
        logger.info("✅ Daily scan scheduled at 6:00 AM")
        
        self.scheduler.add_job(
            func=self._weekly_scan,
            trigger=CronTrigger(day_of_week='mon', hour=7, minute=0),
            id='weekly_scan',
            name='Weekly Full Scan',
            replace_existing=True
        )
        logger.info("✅ Weekly scan scheduled on Monday 7:00 AM")
        
        self.scheduler.add_job(
            func=self._status_check,
            trigger=IntervalTrigger(hours=1),
            id='status_check',
            name='Status Check',
            replace_existing=True
        )
        logger.info("✅ Status check scheduled every hour")
    
    def _daily_scan(self):
        logger.info(f"[{datetime.now()}] Running daily scan...")
        asyncio.run(self._run_scan("daily"))
    
    def _weekly_scan(self):
        logger.info(f"[{datetime.now()}] Running weekly full scan...")
        asyncio.run(self._run_scan("weekly"))
    
    def _status_check(self):
        logger.info(f"[{datetime.now()}] Status check completed")
    
    async def _run_scan(self, scan_type: str):
        try:
            from app.automation.core import run_automated_scan, send_scan_report
            urls = ['axiler.com', 'polysignals.app']
            for url in urls:
                result = await run_automated_scan(url)
                if result.get('success'):
                    await send_scan_report(url, result)
        except Exception as e:
            logger.error(f"Scan error: {e}")
    
    def start(self):
        self.scheduler.start()
        logger.info("🚀 Scheduler started!")
    
    def stop(self):
        self.scheduler.shutdown()
        logger.info("🛑 Scheduler stopped!")
    
    def get_jobs(self):
        return self.scheduler.get_jobs()

scheduler = ScanScheduler()
