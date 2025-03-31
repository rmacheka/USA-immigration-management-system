# tests/test_auth/test_auth_service.py - Tests for authentication service
import pytest
from app.auth.service import AuthService
from app.auth.models import UserRole
from app.auth.utils import verify_password
from app.exceptions import ValidationError, AuthenticationError


def test_create_user(db_session):
    """Test creating a new user"""
    service = AuthService()
    
    user = service.create_user(
        db_session,
        username="testuser",
        email="test@example.com",
        password="Password123!",
        role=UserRole.OFFICER
    )
    
    assert user.id is not None
    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert user.role == UserRole.OFFICER
    # Check that password was properly hashed
    assert user.hashed_password != "Password123!"
    assert verify_password("Password123!", user.hashed_password)


def test_create_duplicate_user(db_session, sample_admin_user):
    """Test creating user with duplicate username fails"""
    service = AuthService()
    
    with pytest.raises(ValidationError):
        service.create_user(
            db_session,
            username=sample_admin_user.username,  # Duplicate username
            email="another@example.com",
            password="Password123!",
            role=UserRole.OFFICER
        )


def test_authenticate_user(db_session, sample_admin_user):
    """Test user authentication"""
    service = AuthService()
    
    # Valid authentication (password is "password" for sample_admin_user)
    user = service.authenticate_user(db_session, "admin", "password")
    assert user.id == sample_admin_user.id
    
    # Invalid password
    with pytest.raises(AuthenticationError):
        service.authenticate_user(db_session, "admin", "wrongpassword")
    
    # Non-existent user
    with pytest.raises(AuthenticationError):
        service.authenticate_user(db_session, "nonexistent", "password")


def test_create_access_token(db_session, sample_admin_user):
    """Test creating an access token"""
    service = AuthService()
    
    token_data = service.create_access_token_for_user(sample_admin_user)
    
    assert "access_token" in token_data
    assert "token_type" in token_data
    assert token_data["token_type"] == "bearer"
    assert len(token_data["access_token"]) > 0

