# models/permit.py - Permit model
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.database import Base


class PermitType(str, enum.Enum):
    WORK = "work"
    STUDENT = "student"
    TOURIST = "tourist"
    BUSINESS = "business"
    PERMANENT = "permanent"


class PermitStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"


class Permit(Base):
    __tablename__ = "permits"

    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"))
    permit_type = Column(Enum(PermitType))
    issue_date = Column(DateTime)
    expiry_date = Column(DateTime)
    is_renewable = Column(Boolean, default=False)
    status = Column(Enum(PermitStatus), default=PermitStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    application = relationship("Application", back_populates="permit")
