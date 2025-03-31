# models/permit.py - Permit model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class PermitType(enum.Enum):
    TOURIST_VISA = "tourist_visa"
    WORK_VISA = "work_visa"
    STUDENT_VISA = "student_visa"
    PERMANENT_RESIDENCE = "permanent_residence"
    CITIZENSHIP = "citizenship"
    ASYLUM = "asylum"


class PermitStatus(enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_ACTIVATION = "pending_activation"


class Permit(Base):
    __tablename__ = "permits"

    id = Column(Integer, primary_key=True, index=True)
    permit_number = Column(String, unique=True, index=True, nullable=False)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    type = Column(Enum(PermitType), nullable=False)
    status = Column(Enum(PermitStatus), default=PermitStatus.PENDING_ACTIVATION)
    issue_date = Column(Date, nullable=False)
    expiry_date = Column(Date, nullable=False)
    is_renewable = Column(Boolean, default=False)
    renewal_reminder_sent = Column(Boolean, default=False)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    application = relationship("Application", back_populates="permit")
