from ..extensions import db

class Country(db.Model):
    __tablename__ = 'countries'
    
    country_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(3), unique=True, nullable=False)  # ISO 3-letter code
    is_restricted = db.Column(db.Boolean, default=False)
    
    # Relationships
    visa_restrictions = db.relationship('VisaType', 
                                     secondary='visa_country_restrictions',
                                     back_populates='restricted_countries')
    
    def __repr__(self):
        return f'<Country {self.code}: {self.name}>'

# Sample data
def seed_countries():
    countries = [
        {'name': 'United States', 'code': 'USA', 'is_restricted': False},
        {'name': 'Canada', 'code': 'CAN', 'is_restricted': False},
        {'name': 'Mexico', 'code': 'MEX', 'is_restricted': False},
        {'name': 'India', 'code': 'IND', 'is_restricted': False},
        {'name': 'China', 'code': 'CHN', 'is_restricted': True}
    ]
    
    for country_data in countries:
        if not Country.query.filter_by(code=country_data['code']).first():
            country = Country(**country_data)
            db.session.add(country)
    db.session.commit()