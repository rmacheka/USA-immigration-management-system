# utils/permit_tracker.py
from apscheduler.schedulers.background import BackgroundScheduler
from app.services import PermitService
from app.extensions import db

class PermitTracker:
    def __init__(self, app):
        self.app = app
        self.scheduler = BackgroundScheduler()
    
    def start(self):
        """Start the scheduled tasks"""
        self.scheduler.add_job(
            self.check_expirations,
            'cron',
            day_of_week='mon-fri',
            hour=1,
            minute=0
        )
        self.scheduler.start()
    
    def check_expirations(self):
        """Check and update expiring permits"""
        with self.app.app_context():
            permit_service = PermitService(db.session)
            
            # Check permits expiring soon (for notifications)
            expiring_soon = permit_service.get_expiring_permits(30)
            self._send_expiration_notices(expiring_soon)
            
            # Update expired permits
            expired = permit_service.get_expired_permits()
            for permit in expired:
                permit_service.update_status(permit.id, 'expired')
            
            log.info(f"Processed {len(expired)} expired permits")