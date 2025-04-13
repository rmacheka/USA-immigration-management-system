from datetime import date
from ..extensions import db

class Document(db.Model):
    __tablename__ = 'documents'
    
    document_id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    document_type = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.Date, nullable=False, default=date.today)
    verified = db.Column(db.Boolean, default=False)
    
    def verify_document(self):
        self.verified = True
        db.session.commit()