# tests/test_services/test_permit_service.py - Tests for permit service
import pytest
from app.services.permit_service import PermitService
from app.models.permit import PermitStatus
from app.exceptions import ValidationError, NotFoundException
from datetime import date, timedelta


def test_create_permit(db_session, sample_approved_application):
    """Test creating a new permit"""
    service = PermitService()
    
    permit = service.create_permit(
        db_session,
        application_id=sample_approved_application.id,
        permit_type=sample_approved_application.type,
        issue_date=date.today(),
        expiry_date=date.today() + timedelta(days=365),
        is_renewable=True
    )
    
    assert permit.id is not None
    assert permit.permit_number is not None
    assert permit.status == PermitStatus.PENDING_ACTIVATION
    assert permit.is_renewable is True


def test_create_permit_invalid_dates(db_session, sample_approved_application):
    """Test creating permit with invalid dates fails"""
    service = PermitService()
    
    # Test expiry date before issue date
    with pytest.raises(ValidationError):
        service.create_permit(
            db_session,
            application_id=sample_approved_application.id,
            permit_type=sample_approved_application.type,
            issue_date=date.today(),
            expiry_date=date.today() - timedelta(days=10)
        )


def test_activate_permit(db_session, sample_permit):
    """Test activating a permit"""
    service = PermitService()
    
    # First set to pending activation
    sample_permit.status = PermitStatus.PENDING_ACTIVATION
    db_session.commit()
    
    # Activate permit
    permit = service.activate_permit(db_session, sample_permit.id)
    assert permit.status == PermitStatus.ACTIVE


def test_revoke_permit(db_session, sample_permit):
    """Test revoking a permit"""
    service = PermitService()
    
    # Ensure permit is active
    sample_permit.status = PermitStatus.ACTIVE
    db_session.commit()
    
    # Revoke permit
    permit = service.revoke_permit(db_session, sample_permit.id, reason="Violation of terms")
    assert permit.status == PermitStatus.REVOKED


def test_get_permits_expiring_soon(db_session):
    """Test getting permits expiring soon"""
    service = PermitService()
    
    # Create permits with different expiry dates
    permits = []
    for i in range(5):
        permit = Permit(
            permit_number=f"PMT-TEST{i}",
            application_id=1,  # This is a test so we don't need a real application
            type=PermitType.TOURIST_VISA,
            status=PermitStatus.ACTIVE,
            issue_date=date.today() - timedelta(days=30),
            expiry_date=date.today() + timedelta(days=i * 10),  # 0, 10, 20, 30, 40 days
            is_renewable=False
        )
        db_session.add(permit)
    
    db_session.commit()
    
    # Get permits expiring in 15 days
    expiring_permits = service.get_permits_expiring_soon(db_session, days=15)
    assert len(expiring_permits) == 2  # Only the first two should be expiring within 15 days

