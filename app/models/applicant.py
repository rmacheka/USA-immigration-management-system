# models/applicant.py - Applicant model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class ApplicantStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    REJECTED = "rejected"


class Applicant(Base):
    __tablename__ = "applicants"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    date_of_birth = Column(Date, nullable=False)
    nationality = Column(String, nullable=False)
    passport_number = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone_number = Column(String)
    status = Column(Enum(ApplicantStatus), default=ApplicantStatus.PENDING)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    applications = relationship("Application", back_populates="applicant")
    documents = relationship("Document", back_populates="applicant")

