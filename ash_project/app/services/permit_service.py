from datetime import datetime, timedelta
from app.models.permit import Permit
from app.extensions import db
from app.utils.logger import log

class PermitService:
    @staticmethod
    def create_permit(permit_data):
        try:
            permit = Permit(
                permit_number=permit_data['permit_number'],
                permit_type=permit_data['permit_type'],
                issue_date=datetime.strptime(permit_data['issue_date'], '%Y-%m-%d').date(),
                expiration_date=datetime.strptime(permit_data['expiration_date'], '%Y-%m-%d').date(),
                applicant_id=permit_data['applicant_id']
            )
            db.session.add(permit)
            db.session.commit()
            log.info(f"Permit {permit.permit_number} created successfully")
            return permit
        except Exception as e:
            db.session.rollback()
            log.error(f"Error creating permit: {str(e)}")
            raise

    @staticmethod
    def check_expiring_permits(days_before=30):
        today = datetime.now().date()
        threshold_date = today + timedelta(days=days_before)
        
        expiring_permits = Permit.query.filter(
            Permit.expiration_date <= threshold_date,
            Permit.expiration_date >= today,
            Permit.status == 'active'
        ).all()
        
        log.info(f"Found {len(expiring_permits)} permits expiring within {days_before} days")
        return expiring_permits

    @staticmethod
    def expire_permits():
        today = datetime.now().date()
        expired_permits = Permit.query.filter(
            Permit.expiration_date < today,
            Permit.status == 'active'
        ).all()
        
        for permit in expired_permits:
            permit.status = 'expired'
            log.info(f"Permit {permit.permit_number} marked as expired")
        
        db.session.commit()
        return expired_permits