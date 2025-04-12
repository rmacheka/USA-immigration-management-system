

from enum import Enum
from datetime import datetime
from app.extensions import db

class PermitStatus(Enum):
    PERMANENT = 'Permanent'
    TEMPORARY = 'Temporary'
    EXPIRED = 'Expired'
    ILLEGAL = 'Illegal'

class Permit(db.Model):
    __tablename__ = 'permits'
    
    id = Column(Integer, primary_key=True)
    applicant_id = Column(Integer, ForeignKey('applicants.id'), nullable=False)
    expiry_date = Column(Date, nullable=False)
    status = Column(db.Enum(PermitStatus), nullable=False, default=PermitStatus.TEMPORARY)
    
    # Relationships
    applicant = db.relationship('Applicant', back_populates='permits')
    
    @property
    def is_expired(self):
        return (self.status == PermitStatus.EXPIRED or 
               (self.expiry_date < datetime.now().date() and 
                self.status != PermitStatus.PERMANENT))
    
    @validates('status')
    def validate_status(self, key, status):
        assert status in [s.value for s in PermitStatus], \
            "Status must be Permanent, Temporary, Expired, or Illegal"
        return status