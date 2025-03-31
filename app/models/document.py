# models/document.py - Document model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class DocumentType(enum.Enum):
    PASSPORT = "passport"
    BIRTH_CERTIFICATE = "birth_certificate"
    MARRIAGE_CERTIFICATE = "marriage_certificate"
    EDUCATIONAL_CERTIFICATE = "educational_certificate"
    EMPLOYMENT_VERIFICATION = "employment_verification"
    BANK_STATEMENT = "bank_statement"
    MEDICAL_REPORT = "medical_report"
    POLICE_CLEARANCE = "police_clearance"
    PHOTO = "photo"
    OTHER = "other"


class DocumentStatus(enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    applicant_id = Column(Integer, ForeignKey("applicants.id"), nullable=False)
    application_id = Column(Integer, ForeignKey("applications.id"))
    type = Column(Enum(DocumentType), nullable=False)
    file_path = Column(String, nullable=False)
    file_name = Column(String, nullable=False)
    mime_type = Column(String, nullable=False)
    upload_date = Column(Date, server_default="now()")
    expiry_date = Column(Date)
    status = Column(Enum(DocumentStatus), default=DocumentStatus.PENDING)
    verification_notes = Column(String)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    applicant = relationship("Applicant", back_populates="documents")
    application = relationship("Application", back_populates="documents")

