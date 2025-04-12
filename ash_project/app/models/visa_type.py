from ..extensions import db

class VisaType(db.Model):
    __tablename__ = 'visa_types'
    
    visa_type_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # e.g., "H1B", "L1"
    category = db.Column(db.String(30))  # "Work", "Student", "Tourist"
    description = db.Column(db.Text)
    processing_time_days = db.Column(db.Integer)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    restricted_countries = db.relationship('Country',
                                        secondary='visa_country_restrictions',
                                        back_populates='visa_restrictions')
    
    def __repr__(self):
        return f'<VisaType {self.name}>'

# Sample data
def seed_visa_types():
    visa_types = [
        {
            'name': 'H1B',
            'category': 'Work',
            'description': 'Specialty occupation visa',
            'processing_time_days': 90
        },
        {
            'name': 'L1',
            'category': 'Work',
            'description': 'Intracompany transfer visa',
            'processing_time_days': 60
        },
        {
            'name': 'F1',
            'category': 'Student',
            'description': 'Academic student visa',
            'processing_time_days': 45
        }
    ]
    
    for visa_data in visa_types:
        if not VisaType.query.filter_by(name=visa_data['name']).first():
            visa = VisaType(**visa_data)
            db.session.add(visa)
    db.session.commit()