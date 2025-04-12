from datetime import datetime
from ..extensions import db

class CaseNote(db.Model):
    __tablename__ = 'case_notes'
    
    note_id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.application_id'), nullable=False)
    officer_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_internal = db.Column(db.Boolean, default=True)  # False = visible to applicant
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    application = db.relationship('ImmigrationApplication', backref='case_notes')
    officer = db.relationship('User', backref='notes_created')
    
    def __repr__(self):
        return f'<CaseNote {self.note_id} for Application {self.application_id}>'