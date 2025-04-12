from apscheduler.schedulers.background import BackgroundScheduler
from app.models import Permit
from app.extensions import db
from datetime import datetime, timedelta

scheduler = BackgroundScheduler()

def check_expiring_permits():
    """Check for permits expiring soon"""
    with scheduler.app.app_context():
        threshold = datetime.utcnow() + timedelta(days=30)
        expiring = Permit.query.filter(
            Permit.expiry_date <= threshold,
            Permit.expiry_date >= datetime.utcnow(),
            Permit.status == 'active'
        ).all()
        
        for permit in expiring:
            NotificationService.create_notification(
                user_id=permit.application.user_id,
                message=f"Your permit {permit.id} expires on {permit.expiry_date}",
                notification_type='permit_expiring'
            )

def init_scheduler(app):
    if not scheduler.running:
        scheduler.app = app
        scheduler.add_job(
            check_expiring_permits,
            'cron',
            day_of_week='mon-fri',
            hour=9
        )
        scheduler.start()