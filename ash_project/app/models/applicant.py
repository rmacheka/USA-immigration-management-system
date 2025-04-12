from app.extensions import db
from sqlalchemy import Column, Integer, String, Date, ForeignKey
from sqlalchemy.orm import validates

class Applicant(db.Model):
    __tablename__ = 'applicants'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    phone = Column(String(15), nullable=False)
    uscis_number = Column(String(9), unique=True, nullable=False)
    profession = Column(String(50))
    address = Column(String(200))
    nationality = Column(String(50))
    
    # Relationships
    permits = db.relationship('Permit', back_populates='applicant')
    
    @validates('uscis_number')
    def validate_uscis_number(self, key, uscis_number):
        assert len(uscis_number) == 9 and uscis_number.isdigit(), "USCIS Number must be exactly 9 digits"
        return uscis_number
    
    @validates('phone')
    def validate_phone(self, key, phone):
        # Basic phone validation - can be enhanced
        assert len(phone) >= 10, "Phone number must be at least 10 digits"
        return phone