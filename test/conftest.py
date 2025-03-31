# Now let's write some unit tests for our services
# tests/conftest.py - Test fixtures
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models.applicant import Applicant, ApplicantStatus
from app.models.application import Application, ApplicationStatus, ApplicationType
from app.models.document import Document, DocumentType, DocumentStatus
from app.models.permit import Permit, PermitStatus, PermitType
from app.auth.models import User, UserRole
from datetime import date, timedelta
import os
import uuid

# Test database URL
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test.db"


@pytest.fixture(scope="session")
def db_engine():
    """Create a test database engine"""
    engine = create_engine(SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    os.remove("./test.db")


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Create a test database session"""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def sample_applicant(db_session):
    """Create a sample applicant"""
    applicant = Applicant(
        first_name="John",
        last_name="Doe",
        date_of_birth=date(1990, 1, 1),
        nationality="Canada",
        passport_number="AB123456",
        email="john.doe@example.com",
        phone_number="+11234567890",
        status=ApplicantStatus.ACTIVE
    )
    db_session.add(applicant)
    db_session.commit()
    db_session.refresh(applicant)
    return applicant


@pytest.fixture
def sample_application(db_session, sample_applicant):
    """Create a sample application"""
    application = Application(
        application_number=f"APP-{uuid.uuid4().hex[:8].upper()}",
        applicant_id=sample_applicant.id,
        type=ApplicationType.TOURIST_VISA,
        status=ApplicationStatus.SUBMITTED,
        submission_date=date.today(),
        notes="Test application"
    )
    db_session.add(application)
    db_session.commit()
    db_session.refresh(application)
    return application


@pytest.fixture
def sample_approved_application(db_session, sample_applicant):
    """Create a sample approved application"""
    application = Application(
        application_number=f"APP-{uuid.uuid4().hex[:8].upper()}",
        applicant_id=sample_applicant.id,
        type=ApplicationType.WORK_VISA,
        status=ApplicationStatus.APPROVED,
        submission_date=date.today() - timedelta(days=10),
        decision_date=date.today(),
        notes="Approved test application"
    )
    db_session.add(application)
    db_session.commit()
    db_session.refresh(application)
    return application


@pytest.fixture
def sample_permit(db_session, sample_approved_application):
    """Create a sample permit"""
    permit = Permit(
        permit_number=f"PMT-{uuid.uuid4().hex[:8].upper()}",
        application_id=sample_approved_application.id,
        type=PermitType.WORK_VISA,
        status=PermitStatus.ACTIVE,
        issue_date=date.today(),
        expiry_date=date.today() + timedelta(days=365),
        is_renewable=True
    )
    db_session.add(permit)
    db_session.commit()
    db_session.refresh(permit)
    return permit


@pytest.fixture
def sample_admin_user(db_session):
    """Create a sample admin user"""
    user = User(
        username="admin",
        email="admin@example.com",
        hashed_password="$2b$12$KQOi8G2DZ2PnQVJKHc3tFOt10gH2AWbcVDsQnW1D.1JsYpbUC/3F6",  # "password"
        role=UserRole.ADMIN,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


