# services/application_service.py - Application service
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date
import uuid
from app.models.application import Application, ApplicationStatus, ApplicationType
from app.models.applicant import Applicant
from app.exceptions import NotFoundException, ValidationError


class ApplicationService:
    def create_application(
        self, db: Session, applicant_id: int, application_type: ApplicationType
    ) -> Application:
        """Create a new application"""
        # Check if applicant exists
        applicant = db.query(Applicant).filter(Applicant.id == applicant_id).first()
        if not applicant:
            raise NotFoundException(f"Applicant with ID {applicant_id} not found")
        
        # Generate unique application number
        application_number = f"APP-{uuid.uuid4().hex[:8].upper()}"
        
        application = Application(
            application_number=application_number,
            applicant_id=applicant_id,
            type=application_type,
            status=ApplicationStatus.DRAFT
        )
        
        db.add(application)
        db.commit()
        db.refresh(application)
        return application
    
    def get_application(self, db: Session, application_id: int) -> Application:
        """Get an application by ID"""
        application = db.query(Application).filter(Application.id == application_id).first()
        if not application:
            raise NotFoundException(f"Application with ID {application_id} not found")
        return application
    
    def get_application_by_number(self, db: Session, application_number: str) -> Application:
        """Get an application by application number"""
        application = db.query(Application).filter(Application.application_number == application_number).first()
        if not application:
            raise NotFoundException(f"Application with number {application_number} not found")
        return application
    
    def get_applications_by_applicant(self, db: Session, applicant_id: int) -> List[Application]:
        """Get all applications for an applicant"""
        return db.query(Application).filter(Application.applicant_id == applicant_id).all()
    
    def update_application_status(
        self, db: Session, application_id: int, status: ApplicationStatus, notes: Optional[str] = None
    ) -> Application:
        """Update an application's status"""
        application = self.get_application(db, application_id)
        
        # Handle status transition logic
        if application.status == ApplicationStatus.DRAFT and status == ApplicationStatus.SUBMITTED:
            application.submission_date = date.today()
        
        if status == ApplicationStatus.APPROVED or status == ApplicationStatus.REJECTED:
            application.decision_date = date.today()
        
        application.status = status
        
        if notes:
            application.notes = notes if not application.notes else f"{application.notes}\n\n{notes}"
        
        db.commit()
        db.refresh(application)
        return application

