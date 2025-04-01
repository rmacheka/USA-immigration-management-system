# auth/models.py - User authentication models
from sqlalchemy import Column, Integer, String, Boolean, Enum, ForeignKey, Date
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class UserRole(enum.Enum):
    ADMIN = "admin"
    OFFICER = "officer"
    SUPERVISOR = "supervisor"
    APPLICANT = "applicant"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Optional link to applicant for applicant users
    applicant_id = Column(Integer, ForeignKey("applicants.id"), nullable=True)


# Let's implement the service layer components for data processing
# services/applicant_service.py - Applicant service
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date
from app.models.applicant import Applicant, ApplicantStatus
from app.exceptions import NotFoundException, ValidationError


class ApplicantService:
    def create_applicant(
        self, db: Session, first_name: str, last_name: str, date_of_birth: date, 
        nationality: str, passport_number: str, email: str, phone_number: Optional[str] = None
    ) -> Applicant:
        """Create a new applicant record"""
        # Validate inputs
        if not first_name or not last_name:
            raise ValidationError("First name and last name are required")
        
        if not passport_number:
            raise ValidationError("Passport number is required")
            
        # Check if passport number already exists
        existing = db.query(Applicant).filter(Applicant.passport_number == passport_number).first()
        if existing:
            raise ValidationError(f"Passport number {passport_number} is already registered")
            
        # Check if email already exists
        if email:
            existing = db.query(Applicant).filter(Applicant.email == email).first()
            if existing:
                raise ValidationError(f"Email {email} is already registered")
        
        # Create applicant
        applicant = Applicant(
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            nationality=nationality,
            passport_number=passport_number,
            email=email,
            phone_number=phone_number,
            status=ApplicantStatus.PENDING
        )
        
        db.add(applicant)
        db.commit()
        db.refresh(applicant)
        return applicant
    
    def get_applicant(self, db: Session, applicant_id: int) -> Applicant:
        """Get an applicant by ID"""
        applicant = db.query(Applicant).filter(Applicant.id == applicant_id).first()
        if not applicant:
            raise NotFoundException(f"Applicant with ID {applicant_id} not found")
        return applicant
    
    def get_applicant_by_passport(self, db: Session, passport_number: str) -> Applicant:
        """Get an applicant by passport number"""
        applicant = db.query(Applicant).filter(Applicant.passport_number == passport_number).first()
        if not applicant:
            raise NotFoundException(f"Applicant with passport {passport_number} not found")
        return applicant
    
    def update_applicant_status(self, db: Session, applicant_id: int, status: ApplicantStatus) -> Applicant:
        """Update an applicant's status"""
        applicant = self.get_applicant(db, applicant_id)
        applicant.status = status
        db.commit()
        db.refresh(applicant)
        return applicant
    
    def update_applicant(self, db: Session, applicant_id: int, **kwargs) -> Applicant:
        """Update applicant details"""
        applicant = self.get_applicant(db, applicant_id)
        
        # Update attributes that are provided
        for key, value in kwargs.items():
            if hasattr(applicant, key) and value is not None:
                setattr(applicant, key, value)
        
        db.commit()
        db.refresh(applicant)
        return applicant

