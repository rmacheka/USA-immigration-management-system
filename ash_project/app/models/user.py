from ash_project.app.extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
#from .role import Role  # Import Role model
from .application import Application
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Increased length to accommodate modern password hashes
    #password_hash = db.Column(db.String(256))
    password_hash = db.Column(db.String(512))
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'officer', 'staff'
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)
    
    # Relationships
    processed_applications = db.relationship(
        'Application', 
        foreign_keys='Application.processing_officer_id', 
        backref='processing_officer', 
        lazy=True
    )
    # Add relationship to SearchHistory
    search_history = db.relationship('SearchHistory', back_populates='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'