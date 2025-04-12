from datetime import datetime
from enum import Enum
from app.extensions import db

class ApplicationStatus(Enum):
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'
    IN_REVIEW = 'in_review'

class Application(db.Model):
    __tablename__ = 'applications'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10))
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    visa_type = db.Column(db.String(30), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    duration_days = db.Column(db.Integer, nullable=False)
    passport_path = db.Column(db.String(200), nullable=False)
    photo_path = db.Column(db.String(200), nullable=False)
    status = db.Column(db.Enum(ApplicationStatus), 
               default=ApplicationStatus.PENDING,
               nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, 
                          onupdate=datetime.utcnow)
    
    # Relationships
    documents = db.relationship('Document', backref='application', lazy=True)
    permits = db.relationship('Permit', backref='application', lazy=True)
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"