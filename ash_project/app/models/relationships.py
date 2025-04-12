from ..extensions import db

# Association table for visa type-country restrictions
visa_country_restrictions = db.Table('visa_country_restrictions',
    db.Column('visa_type_id', db.Integer, db.ForeignKey('visa_types.visa_type_id'), primary_key=True),
    db.Column('country_id', db.Integer, db.ForeignKey('countries.country_id'), primary_key=True),
    db.Column('restriction_notes', db.Text)
)