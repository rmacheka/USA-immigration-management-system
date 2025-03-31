# models/application.py - Application model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class ApplicationType(enum.Enum):
    TOURIST_VISA = "tourist_visa"
    WORK_VISA = "work_visa"
    STUDENT_VISA = "student_visa"
    PERMANENT_RESIDENCE = "permanent_residence"
    CITIZENSHIP = "citizenship"
    ASYLUM = "asylum"


class ApplicationStatus(enum.Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    ADDITIONAL_INFO_REQUIRED = "additional_info_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    application_number = Column(String, unique=True, index=True, nullable=False)
    applicant_id = Column(Integer, ForeignKey("applicants.id"), nullable=False)
    type = Column(Enum(ApplicationType), nullable=False)
    status = Column(Enum(ApplicationStatus), default=ApplicationStatus.DRAFT)
    submission_date = Column(Date)
    decision_date = Column(Date)
    notes = Column(Text)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    applicant = relationship("Applicant", back_populates="applications")
    documents = relationship("Document", back_populates="application")
    permit = relationship("Permit", back_populates="application", uselist=False)
