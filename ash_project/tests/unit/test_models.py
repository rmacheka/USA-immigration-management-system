import pytest
from datetime import date, timedelta
from app.models.user import User
from app.models.permit import Permit
from app.extensions import db

@pytest.fixture
def sample_user():
    user = User(
        username='testuser',
        email='test@example.com',
        role='staff'
    )
    user.set_password('testpass')
    return user

@pytest.fixture
def sample_permit():
    return Permit(
        permit_number='TEST123',
        permit_type='H1B',
        issue_date=date.today(),
        expiration_date=date.today() + timedelta(days=365),
        applicant_id=1
    )

def test_user_creation(sample_user):
    assert sample_user.username == 'testuser'
    assert sample_user.check_password('testpass')
    assert not sample_user.check_password('wrongpass')

def test_permit_expiration(sample_permit):
    assert not sample_permit.is_expired
    sample_permit.expiration_date = date.today() - timedelta(days=1)
    assert sample_permit.is_expired

def test_permit_status(sample_permit):
    assert sample_permit.status == 'active'
    sample_permit.revoke()
    assert sample_permit.status == 'revoked'