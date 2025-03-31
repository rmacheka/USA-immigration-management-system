# services/permit_service.py - Permit service for tracking and expiration
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date, timedelta
import uuid
from app.models.permit import Permit, PermitStatus, PermitType
from app.models.application import Application, ApplicationStatus
from app.exceptions import NotFoundException, ValidationError


class PermitService:
    def create_permit(
        self, db: Session, application_id: int, permit_type: PermitType, 
        issue_date: date, expiry_date: date, is_renewable: bool = False
    ) -> Permit:
        """Create a new permit for an approved application"""
        # Check if application exists and is approved
        application = db.query(Application).filter(Application.id == application_id).first()
        if not application:
            raise NotFoundException(f"Application with ID {application_id} not found")
        
        if application.status != ApplicationStatus.APPROVED:
            raise ValidationError("Cannot create permit for non-approved application")
        
        # Validate dates
        if issue_date > expiry_date:
            raise ValidationError("Issue date cannot be after expiry date")
        
        if issue_date < date.today():
            raise ValidationError("Issue date cannot be in the past")
        
        # Generate unique permit number
        permit_number = f"PMT-{uuid.uuid4().hex[:8].upper()}"
        
        permit = Permit(
            permit_number=permit_number,
            application_id=application_id,
            type=permit_type,
            status=PermitStatus.PENDING_ACTIVATION,
            issue_date=issue_date,
            expiry_date=expiry_date,
            is_renewable=is_renewable
        )
        
        db.add(permit)
        db.commit()
        db.refresh(permit)
        return permit
    
    def get_permit(self, db: Session, permit_id: int) -> Permit:
        """Get a permit by ID"""
        permit = db.query(Permit).filter(Permit.id == permit_id).first()
        if not permit:
            raise NotFoundException(f"Permit with ID {permit_id} not found")
        return permit
    
    def get_permit_by_number(self, db: Session, permit_number: str) -> Permit:
        """Get a permit by permit number"""
        permit = db.query(Permit).filter(Permit.permit_number == permit_number).first()
        if not permit:
            raise NotFoundException(f"Permit with number {permit_number} not found")
        return permit
    
    def get_permits_expiring_soon(self, db: Session, days: int = 30) -> List[Permit]:
        """Get all permits expiring within the specified number of days"""
        expiry_threshold = date.today() + timedelta(days=days)
        return db.query(Permit).filter(
            Permit.status == PermitStatus.ACTIVE,
            Permit.expiry_date <= expiry_threshold
        ).all()
    
    def activate_permit(self, db: Session, permit_id: int) -> Permit:
        """Activate a pending permit"""
        permit = self.get_permit(db, permit_id)
        
        if permit.status != PermitStatus.PENDING_ACTIVATION:
            raise ValidationError(f"Cannot activate permit with status {permit.status}")
        
        permit.status = PermitStatus.ACTIVE
        db.commit()
        db.refresh(permit)
        return permit
    
    def revoke_permit(self, db: Session, permit_id: int, reason: str) -> Permit:
        """Revoke an active permit"""
        permit = self.get_permit(db, permit_id)
        
        if permit.status != PermitStatus.ACTIVE:
            raise ValidationError(f"Cannot revoke permit with status {permit.status}")
        
        permit.status = PermitStatus.REVOKED
        # Additional logic to log the reason could be added here
        
        db.commit()
        db.refresh(permit)
        return permit
    
    def check_expired_permits(self, db: Session) -> List[Permit]:
        """Check and update status of expired permits"""
        today = date.today()
        expired_permits = db.query(Permit).filter(
            Permit.status == PermitStatus.ACTIVE,
            Permit.expiry_date < today
        ).all()
        
        for permit in expired_permits:
            permit.status = PermitStatus.EXPIRED
        
        if expired_permits:
            db.commit()
        
        return expired_permits

