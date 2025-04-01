from sqlalchemy.orm import Session
from datetime import datetime
from app.models.application import Application
from app.models.permit import Permit

class ReportService:
    def generate_applications_report(self, db: Session, start_date: datetime, end_date: datetime):
        """Generate applications report for the given date range"""
        return db.query(Application).filter(
            Application.submission_date.between(start_date, end_date)
        ).all()

    def generate_permits_report(self, db: Session, start_date: datetime, end_date: datetime):
        """Generate permits report for the given date range"""
        return db.query(Permit).filter(
            Permit.issue_date.between(start_date, end_date)
        ).all() 