# auth/service.py - Authentication service
from sqlalchemy.orm import Session
from typing import Optional
from datetime import timedelta
from app.auth.models import User, UserRole
from app.auth.utils import verify_password, get_password_hash, create_access_token
from app.config import settings
from app.exceptions import AuthenticationError, ValidationError


class AuthService:
    def authenticate_user(self, db: Session, username: str, password: str) -> User:
        """Authenticate a user by username and password"""
        user = db.query(User).filter(User.username == username).first()
        
        if not user:
            raise AuthenticationError("Invalid username or password")
        
        if not verify_password(password, user.hashed_password):
            raise AuthenticationError("Invalid username or password")
        
        if not user.is_active:
            raise AuthenticationError("User account is disabled")
        
        return user
    
    def create_user(
        self, db: Session, username: str, email: str, password: str, role: UserRole, 
        applicant_id: Optional[int] = None
    ) -> User:
        """Create a new user"""
        # Check if username already exists
        if db.query(User).filter(User.username == username).first():
            raise ValidationError(f"Username {username} already registered")
        
        # Check if email already exists
        if db.query(User).filter(User.email == email).first():
            raise ValidationError(f"Email {email} already registered")
        
        # Create user with hashed password
        hashed_password = get_password_hash(password)
        user = User(
            username=username,
            email=email, 
            hashed_password=hashed_password,
            role=role,
            applicant_id=applicant_id
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    
    def create_access_token_for_user(self, user: User) -> dict:
        """Create access token for a user"""
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role.value},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

