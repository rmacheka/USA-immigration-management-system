from apscheduler.schedulers.background import BackgroundScheduler
from ..models.permit import Permit, PermitStatus
from ..extensions import db
from datetime import datetime, timedelta, date
from ..services.permit_service import PermitService
from ..services.notification_services import NotificationService
import logging

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler(daemon=True)

def check_permits_job():
    """Job to check for expiring and expired permits."""
    if not scheduler.app:
        logger.error("Scheduler job running without Flask app context!")
        return
        
    with scheduler.app.app_context():
        logger.info("Running scheduled permit check...")
        try:
            days_threshold = 30
            expiring_soon = PermitService.get_expiring_permits(days_threshold)
            logger.info(f"Found {len(expiring_soon)} permits expiring within {days_threshold} days.")
            for permit in expiring_soon:
                if hasattr(permit, 'applicant') and permit.applicant:
                    user_id = permit.applicant.user_id 
                    if user_id:
                        NotificationService.create_notification(
                            user_id=user_id,
                            message=f"Your permit {permit.permit_number} expires on {permit.expiration_date.strftime('%Y-%m-%d')}",
                            notification_type='permit_expiring',
                            related_entity_id=permit.id
                        )
                    else:
                         logger.warning(f"Permit {permit.id} is expiring but applicant {permit.applicant_id} has no associated user_id.")
                else:
                    logger.warning(f"Permit {permit.id} is expiring but has no associated applicant information.")

            expired = PermitService.get_expired_permits()
            logger.info(f"Found {len(expired)} active permits that have expired.")
            count_updated = 0
            for permit in expired:
                try:
                    PermitService.update_permit_status(permit.id, PermitStatus.EXPIRED.value)
                    count_updated += 1
                    if hasattr(permit, 'applicant') and permit.applicant and permit.applicant.user_id:
                         NotificationService.create_notification(
                            user_id=permit.applicant.user_id,
                            message=f"Your permit {permit.permit_number} expired on {permit.expiration_date.strftime('%Y-%m-%d')}",
                            notification_type='permit_expired',
                            related_entity_id=permit.id
                        )
                except Exception as update_err:
                    logger.error(f"Error updating status for expired permit {permit.id}: {update_err}")
            if count_updated > 0:
                 logger.info(f"Updated status for {count_updated} expired permits.")

        except Exception as e:
            logger.error(f"Error during scheduled permit check: {e}", exc_info=True)

def init_scheduler(app):
    if not scheduler.running:
        logger.info("Initializing and starting scheduler...")
        scheduler.app = app
        scheduler.add_job(
            check_permits_job,
            'cron',
            minute='*/5'
        )
        try:
            scheduler.start()
            logger.info("Scheduler started.")
        except Exception as e:
             logger.error(f"Error starting scheduler: {e}", exc_info=True)