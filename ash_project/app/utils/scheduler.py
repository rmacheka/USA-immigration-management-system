from apscheduler.schedulers.background import BackgroundScheduler
from app.services.permit_service import PermitService
from app.utils.logger import log
from datetime import datetime

scheduler = BackgroundScheduler()

def check_expiring_permits_job():
    log.info("Running scheduled job: Checking expiring permits")
    try:
        PermitService.check_expiring_permits()
        PermitService.expire_permits()
    except Exception as e:
        log.error(f"Error in scheduled job: {str(e)}")

def init_scheduler(app):
    if not scheduler.running:
        scheduler.add_job(
            func=check_expiring_permits_job,
            trigger='cron',
            day_of_week='mon-fri',
            hour=9,
            minute=0
        )
        scheduler.start()
        app.logger.info("Scheduler initialized and started")