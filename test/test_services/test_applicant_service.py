# tests/test_services/test_applicant_service.py - Tests for applicant service
import pytest
from app.services.applicant_service import ApplicantService
from app.models.applicant import ApplicantStatus
from app.exceptions import ValidationError, NotFoundException
from datetime import date


def test_create_applicant(db_session):
    """Test creating a new applicant"""
    service = ApplicantService()
    
    applicant = service.create_applicant(
        db_session,
        first_name="Jane",
        last_name="Smith",
        date_of_birth=date(1985, 5, 15),
        nationality="USA",
        passport_number="US123456",
        email="jane.smith@example.com",
        phone_number="+11234567890"
    )
    
    assert applicant.id is not None
    assert applicant.first_name == "Jane"
    assert applicant.last_name == "Smith"
    assert applicant.nationality == "USA"
    assert applicant.status == ApplicantStatus.PENDING


def test_create_applicant_duplicate_passport(db_session, sample_applicant):
    """Test creating applicant with duplicate passport fails"""
    service = ApplicantService()
    
    with pytest.raises(ValidationError):
        service.create_applicant(
            db_session,
            first_name="Another",
            last_name="Person",
            date_of_birth=date(1985, 5, 15),
            nationality="USA",
            passport_number=sample_applicant.passport_number,  # Duplicate passport
            email="another.person@example.com"
        )


def test_get_applicant(db_session, sample_applicant):
    """Test retrieving an applicant by ID"""
    service = ApplicantService()
    
    # Get by valid ID
    applicant = service.get_applicant(db_session, sample_applicant.id)
    assert applicant.id == sample_applicant.id
    assert applicant.first_name == sample_applicant.first_name
    
    # Try to get by invalid ID
    with pytest.raises(NotFoundException):
        service.get_applicant(db_session, 9999)


def test_update_applicant_status(db_session, sample_applicant):
    """Test updating an applicant's status"""
    service = ApplicantService()
    
    # Update status
    applicant = service.update_applicant_status(
        db_session, sample_applicant.id, ApplicantStatus.REJECTED
    )
    
    assert applicant.status == ApplicantStatus.REJECTED


