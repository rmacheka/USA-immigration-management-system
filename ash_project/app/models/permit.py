#.\venv\Scripts\Activate.ps1
from sqlalchemy import Column, Integer, String, Date, Enum as PyEnum, ForeignKey
from enum import Enum
from datetime import datetime
from app.extensions import db

class PermitType(Enum):
    TOURIST = 'tourist'
    WORK = 'work'
    STUDENT = 'student'
    OTHER = 'other'

class PermitStatus(Enum):
    ACTIVE = 'active'
    EXPIRED = 'expired'
    REVOKED = 'revoked'
    PENDING = 'pending'

class Permit(db.Model):
    __tablename__ = 'permits'
    
    id = Column(Integer, primary_key=True)
    applicant_id = Column(Integer, ForeignKey('applicants.id'), nullable=False)
    permit_number = Column(String(50), unique=True, nullable=False)
    permit_type = Column(PyEnum(PermitType), nullable=False)
    status = Column(PyEnum(PermitStatus), default=PermitStatus.PENDING)
    issue_date = Column(Date)
    expiration_date = Column(Date)
    created_at = Column(db.DateTime, default=datetime.utcnow)
    updated_at = Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    applicant = db.relationship('Applicant', back_populates='permits')
    
    @property
    def is_expired(self):
        return self.expiration_date and self.expiration_date < datetime.date.today()
    
    def revoke(self):
        self.status = PermitStatus.REVOKED
        db.session.add(self)
        db.session.commit()