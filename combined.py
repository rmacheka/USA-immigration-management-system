# File structure for the project
'''
immigration_system/
├── alembic/                  # Database migrations
├── app/
│   ├── __init__.py
│   ├── auth/                 # Authentication and authorization
│   │   ├── __init__.py
│   │   ├── dependencies.py   # Auth dependencies for routes
│   │   ├── models.py         # User models
│   │   ├── service.py        # Auth business logic
│   │   └── utils.py          # JWT handling, password hashing, etc.
│   ├── config.py             # App configuration
│   ├── database.py           # Database connection setup
│   ├── exceptions.py         # Custom exceptions
│   ├── logging_config.py     # Logging configuration
│   ├── models/               # SQLAlchemy models
│   │   ├── __init__.py
│   │   ├── applicant.py
│   │   ├── application.py
│   │   ├── document.py
│   │   └── permit.py
│   ├── services/             # Business logic
│   │   ├── __init__.py
│   │   ├── applicant_service.py
│   │   ├── application_service.py
│   │   ├── document_service.py
│   │   └── permit_service.py
│   └── utils/                # Utility functions
│       ├── __init__.py
│       ├── date_utils.py
│       ├── validators.py
│       └── notifications.py
├── tests/                    # Unit tests
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_auth/
│   ├── test_models/
│   └── test_services/
├── .env                      # Environment variables
├── alembic.ini               # Alembic configuration
├── requirements.txt          # Dependencies
└── setup.py                  # Package configuration
'''

# Let's start with the database models using SQLAlchemy ORM
# database.py - Database setup
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# models/applicant.py - Applicant model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class ApplicantStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    REJECTED = "rejected"


class Applicant(Base):
    __tablename__ = "applicants"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    date_of_birth = Column(Date, nullable=False)
    nationality = Column(String, nullable=False)
    passport_number = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone_number = Column(String)
    status = Column(Enum(ApplicantStatus), default=ApplicantStatus.PENDING)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    applications = relationship("Application", back_populates="applicant")
    documents = relationship("Document", back_populates="applicant")


# models/application.py - Application model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class ApplicationType(enum.Enum):
    TOURIST_VISA = "tourist_visa"
    WORK_VISA = "work_visa"
    STUDENT_VISA = "student_visa"
    PERMANENT_RESIDENCE = "permanent_residence"
    CITIZENSHIP = "citizenship"
    ASYLUM = "asylum"


class ApplicationStatus(enum.Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    ADDITIONAL_INFO_REQUIRED = "additional_info_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    application_number = Column(String, unique=True, index=True, nullable=False)
    applicant_id = Column(Integer, ForeignKey("applicants.id"), nullable=False)
    type = Column(Enum(ApplicationType), nullable=False)
    status = Column(Enum(ApplicationStatus), default=ApplicationStatus.DRAFT)
    submission_date = Column(Date)
    decision_date = Column(Date)
    notes = Column(Text)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    applicant = relationship("Applicant", back_populates="applications")
    documents = relationship("Document", back_populates="application")
    permit = relationship("Permit", back_populates="application", uselist=False)


# models/document.py - Document model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class DocumentType(enum.Enum):
    PASSPORT = "passport"
    BIRTH_CERTIFICATE = "birth_certificate"
    MARRIAGE_CERTIFICATE = "marriage_certificate"
    EDUCATIONAL_CERTIFICATE = "educational_certificate"
    EMPLOYMENT_VERIFICATION = "employment_verification"
    BANK_STATEMENT = "bank_statement"
    MEDICAL_REPORT = "medical_report"
    POLICE_CLEARANCE = "police_clearance"
    PHOTO = "photo"
    OTHER = "other"


class DocumentStatus(enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    applicant_id = Column(Integer, ForeignKey("applicants.id"), nullable=False)
    application_id = Column(Integer, ForeignKey("applications.id"))
    type = Column(Enum(DocumentType), nullable=False)
    file_path = Column(String, nullable=False)
    file_name = Column(String, nullable=False)
    mime_type = Column(String, nullable=False)
    upload_date = Column(Date, server_default="now()")
    expiry_date = Column(Date)
    status = Column(Enum(DocumentStatus), default=DocumentStatus.PENDING)
    verification_notes = Column(String)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    applicant = relationship("Applicant", back_populates="documents")
    application = relationship("Application", back_populates="documents")


# models/permit.py - Permit model
from sqlalchemy import Column, Integer, String, Date, Enum, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class PermitType(enum.Enum):
    TOURIST_VISA = "tourist_visa"
    WORK_VISA = "work_visa"
    STUDENT_VISA = "student_visa"
    PERMANENT_RESIDENCE = "permanent_residence"
    CITIZENSHIP = "citizenship"
    ASYLUM = "asylum"


class PermitStatus(enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_ACTIVATION = "pending_activation"


class Permit(Base):
    __tablename__ = "permits"

    id = Column(Integer, primary_key=True, index=True)
    permit_number = Column(String, unique=True, index=True, nullable=False)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    type = Column(Enum(PermitType), nullable=False)
    status = Column(Enum(PermitStatus), default=PermitStatus.PENDING_ACTIVATION)
    issue_date = Column(Date, nullable=False)
    expiry_date = Column(Date, nullable=False)
    is_renewable = Column(Boolean, default=False)
    renewal_reminder_sent = Column(Boolean, default=False)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Relationships
    application = relationship("Application", back_populates="permit")


# auth/models.py - User authentication models
from sqlalchemy import Column, Integer, String, Boolean, Enum, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class UserRole(enum.Enum):
    ADMIN = "admin"
    OFFICER = "officer"
    SUPERVISOR = "supervisor"
    APPLICANT = "applicant"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(Date, server_default="now()")
    updated_at = Column(Date, server_default="now()", onupdate="now()")

    # Optional link to applicant for applicant users
    applicant_id = Column(Integer, ForeignKey("applicants.id"), nullable=True)


# Let's implement the service layer components for data processing
# services/applicant_service.py - Applicant service
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date
from app.models.applicant import Applicant, ApplicantStatus
from app.exceptions import NotFoundException, ValidationError


class ApplicantService:
    def create_applicant(
        self, db: Session, first_name: str, last_name: str, date_of_birth: date, 
        nationality: str, passport_number: str, email: str, phone_number: Optional[str] = None
    ) -> Applicant:
        """Create a new applicant record"""
        # Validate inputs
        if not first_name or not last_name:
            raise ValidationError("First name and last name are required")
        
        if not passport_number:
            raise ValidationError("Passport number is required")
            
        # Check if passport number already exists
        existing = db.query(Applicant).filter(Applicant.passport_number == passport_number).first()
        if existing:
            raise ValidationError(f"Passport number {passport_number} is already registered")
            
        # Check if email already exists
        if email:
            existing = db.query(Applicant).filter(Applicant.email == email).first()
            if existing:
                raise ValidationError(f"Email {email} is already registered")
        
        # Create applicant
        applicant = Applicant(
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            nationality=nationality,
            passport_number=passport_number,
            email=email,
            phone_number=phone_number,
            status=ApplicantStatus.PENDING
        )
        
        db.add(applicant)
        db.commit()
        db.refresh(applicant)
        return applicant
    
    def get_applicant(self, db: Session, applicant_id: int) -> Applicant:
        """Get an applicant by ID"""
        applicant = db.query(Applicant).filter(Applicant.id == applicant_id).first()
        if not applicant:
            raise NotFoundException(f"Applicant with ID {applicant_id} not found")
        return applicant
    
    def get_applicant_by_passport(self, db: Session, passport_number: str) -> Applicant:
        """Get an applicant by passport number"""
        applicant = db.query(Applicant).filter(Applicant.passport_number == passport_number).first()
        if not applicant:
            raise NotFoundException(f"Applicant with passport {passport_number} not found")
        return applicant
    
    def update_applicant_status(self, db: Session, applicant_id: int, status: ApplicantStatus) -> Applicant:
        """Update an applicant's status"""
        applicant = self.get_applicant(db, applicant_id)
        applicant.status = status
        db.commit()
        db.refresh(applicant)
        return applicant
    
    def update_applicant(self, db: Session, applicant_id: int, **kwargs) -> Applicant:
        """Update applicant details"""
        applicant = self.get_applicant(db, applicant_id)
        
        # Update attributes that are provided
        for key, value in kwargs.items():
            if hasattr(applicant, key) and value is not None:
                setattr(applicant, key, value)
        
        db.commit()
        db.refresh(applicant)
        return applicant


# services/application_service.py - Application service
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date
import uuid
from app.models.application import Application, ApplicationStatus, ApplicationType
from app.models.applicant import Applicant
from app.exceptions import NotFoundException, ValidationError


class ApplicationService:
    def create_application(
        self, db: Session, applicant_id: int, application_type: ApplicationType
    ) -> Application:
        """Create a new application"""
        # Check if applicant exists
        applicant = db.query(Applicant).filter(Applicant.id == applicant_id).first()
        if not applicant:
            raise NotFoundException(f"Applicant with ID {applicant_id} not found")
        
        # Generate unique application number
        application_number = f"APP-{uuid.uuid4().hex[:8].upper()}"
        
        application = Application(
            application_number=application_number,
            applicant_id=applicant_id,
            type=application_type,
            status=ApplicationStatus.DRAFT
        )
        
        db.add(application)
        db.commit()
        db.refresh(application)
        return application
    
    def get_application(self, db: Session, application_id: int) -> Application:
        """Get an application by ID"""
        application = db.query(Application).filter(Application.id == application_id).first()
        if not application:
            raise NotFoundException(f"Application with ID {application_id} not found")
        return application
    
    def get_application_by_number(self, db: Session, application_number: str) -> Application:
        """Get an application by application number"""
        application = db.query(Application).filter(Application.application_number == application_number).first()
        if not application:
            raise NotFoundException(f"Application with number {application_number} not found")
        return application
    
    def get_applications_by_applicant(self, db: Session, applicant_id: int) -> List[Application]:
        """Get all applications for an applicant"""
        return db.query(Application).filter(Application.applicant_id == applicant_id).all()
    
    def update_application_status(
        self, db: Session, application_id: int, status: ApplicationStatus, notes: Optional[str] = None
    ) -> Application:
        """Update an application's status"""
        application = self.get_application(db, application_id)
        
        # Handle status transition logic
        if application.status == ApplicationStatus.DRAFT and status == ApplicationStatus.SUBMITTED:
            application.submission_date = date.today()
        
        if status == ApplicationStatus.APPROVED or status == ApplicationStatus.REJECTED:
            application.decision_date = date.today()
        
        application.status = status
        
        if notes:
            application.notes = notes if not application.notes else f"{application.notes}\n\n{notes}"
        
        db.commit()
        db.refresh(application)
        return application


# services/permit_service.py - Permit service for tracking and expiration
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import date, timedelta
import uuid
from app.models.permit import Permit, PermitStatus, PermitType
from app.models.application import Application, ApplicationStatus
from app.exceptions import NotFoundException, ValidationError


class PermitService:
    def create_permit(
        self, db: Session, application_id: int, permit_type: PermitType, 
        issue_date: date, expiry_date: date, is_renewable: bool = False
    ) -> Permit:
        """Create a new permit for an approved application"""
        # Check if application exists and is approved
        application = db.query(Application).filter(Application.id == application_id).first()
        if not application:
            raise NotFoundException(f"Application with ID {application_id} not found")
        
        if application.status != ApplicationStatus.APPROVED:
            raise ValidationError("Cannot create permit for non-approved application")
        
        # Validate dates
        if issue_date > expiry_date:
            raise ValidationError("Issue date cannot be after expiry date")
        
        if issue_date < date.today():
            raise ValidationError("Issue date cannot be in the past")
        
        # Generate unique permit number
        permit_number = f"PMT-{uuid.uuid4().hex[:8].upper()}"
        
        permit = Permit(
            permit_number=permit_number,
            application_id=application_id,
            type=permit_type,
            status=PermitStatus.PENDING_ACTIVATION,
            issue_date=issue_date,
            expiry_date=expiry_date,
            is_renewable=is_renewable
        )
        
        db.add(permit)
        db.commit()
        db.refresh(permit)
        return permit
    
    def get_permit(self, db: Session, permit_id: int) -> Permit:
        """Get a permit by ID"""
        permit = db.query(Permit).filter(Permit.id == permit_id).first()
        if not permit:
            raise NotFoundException(f"Permit with ID {permit_id} not found")
        return permit
    
    def get_permit_by_number(self, db: Session, permit_number: str) -> Permit:
        """Get a permit by permit number"""
        permit = db.query(Permit).filter(Permit.permit_number == permit_number).first()
        if not permit:
            raise NotFoundException(f"Permit with number {permit_number} not found")
        return permit
    
    def get_permits_expiring_soon(self, db: Session, days: int = 30) -> List[Permit]:
        """Get all permits expiring within the specified number of days"""
        expiry_threshold = date.today() + timedelta(days=days)
        return db.query(Permit).filter(
            Permit.status == PermitStatus.ACTIVE,
            Permit.expiry_date <= expiry_threshold
        ).all()
    
    def activate_permit(self, db: Session, permit_id: int) -> Permit:
        """Activate a pending permit"""
        permit = self.get_permit(db, permit_id)
        
        if permit.status != PermitStatus.PENDING_ACTIVATION:
            raise ValidationError(f"Cannot activate permit with status {permit.status}")
        
        permit.status = PermitStatus.ACTIVE
        db.commit()
        db.refresh(permit)
        return permit
    
    def revoke_permit(self, db: Session, permit_id: int, reason: str) -> Permit:
        """Revoke an active permit"""
        permit = self.get_permit(db, permit_id)
        
        if permit.status != PermitStatus.ACTIVE:
            raise ValidationError(f"Cannot revoke permit with status {permit.status}")
        
        permit.status = PermitStatus.REVOKED
        # Additional logic to log the reason could be added here
        
        db.commit()
        db.refresh(permit)
        return permit
    
    def check_expired_permits(self, db: Session) -> List[Permit]:
        """Check and update status of expired permits"""
        today = date.today()
        expired_permits = db.query(Permit).filter(
            Permit.status == PermitStatus.ACTIVE,
            Permit.expiry_date < today
        ).all()
        
        for permit in expired_permits:
            permit.status = PermitStatus.EXPIRED
        
        if expired_permits:
            db.commit()
        
        return expired_permits


# Let's implement the authentication system
# auth/utils.py - Authentication utilities
from datetime import datetime, timedelta
from typing import Optional
import jwt
from passlib.context import CryptContext
from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


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


# auth/dependencies.py - Authentication dependencies
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
import jwt
from sqlalchemy.orm import Session
from app.auth.models import User, UserRole
from app.config import settings
from app.database import get_db
from typing import Optional

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    """Get the current user from the token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    return current_user


def role_required(required_roles: list[UserRole]):
    """Dependency for role-based access control"""
    def check_role(current_user: User = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {[r.value for r in required_roles]}"
            )
        return current_user
    return check_role


# Let's implement error handling and logging
# exceptions.py - Custom exceptions
class BaseAppException(Exception):
    """Base application exception"""
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class NotFoundException(BaseAppException):
    """Exception raised when a resource is not found"""
    pass


class ValidationError(BaseAppException):
    """Exception raised when validation fails"""
    pass


class AuthenticationError(BaseAppException):
    """Exception raised for authentication issues"""
    pass


class AuthorizationError(BaseAppException):
    """Exception raised for authorization issues"""
    pass


# logging_config.py - Logging configuration
import logging
import sys
from logging.handlers import RotatingFileHandler
import os
from app.config import settings

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)


def setup_logging():
    """Setup application logging"""
    # Create logger
    logger = logging.getLogger("app")
    logger.setLevel(logging.INFO if settings.ENVIRONMENT == "production" else logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
    )
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler for rotating log files
    file_handler = RotatingFileHandler(
        "logs/app.log", maxBytes=10485760, backupCount=5  # 10MB
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger


logger = setup_logging()


# Let's create utility functions for common operations
# utils/date_utils.py - Date utility functions
from datetime import date, datetime, timedelta
from typing import Tuple, Optional


def calculate_date_difference(start_date: date, end_date: date) -> int:
    """Calculate the difference in days between two dates"""
    return (end_date - start_date).days


def calculate_visa_duration(months: int) -> Tuple[date, date]:
    """Calculate issue and expiry dates for a visa with specified duration in months"""
    issue_date = date.today()
    expiry_date = issue_date + timedelta(days=30 * months)
    return issue_date, expiry_date


def is_valid_birth_date(birth_date: date) -> bool:
    """Check if a birth date is valid (not in future and person is at least 1 year old)"""
    today = date.today()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    return birth_date < today and age >= 1


def is_date_in_range(check_date: date, start_date: date, end_date: date) -> bool:
    """Check if a date is within a specified range"""
    return start_date <= check_date <= end_date


def format_date(date_obj: date, format_str: str = "%Y-%m-%d") -> str:
    """Format a date object as a string"""
    return date_obj.strftime(format_str)


def parse_date(date_str: str, format_str: str = "%Y-%m-%d") -> Optional[date]:
    """Parse a date string into a date object"""
    try:
        return datetime.strptime(date_str, format_str).date()
    except ValueError:
        return None


# utils/validators.py - Validation utility functions
import re
from datetime import date
from typing import Optional


def is_valid_email(email: str) -> bool:
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_phone_number(phone: str) -> bool:
    """Validate phone number format (supports international formats)"""
    pattern = r"^\+?[0-9]{10,15}$"
    return bool(re.match(pattern, phone))


def is_valid_passport_number(passport: str) -> bool:
    """Validate passport number format (basic check)"""
    # This is a simplified validation - real validation would depend on country-specific formats
    pattern = r"^[A-Z0-9]{6,12}$"
    return bool(re.match(pattern, passport))


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength"""
    def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength
    Returns a tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets strength requirements"


def sanitize_input(input_str: Optional[str]) -> Optional[str]:
    """Sanitize input string to prevent injection attacks"""
    if input_str is None:
        return None
    
    # Remove potentially dangerous HTML/script tags
    sanitized = re.sub(r"<[^>]*>", "", input_str)
    
    # Escape special characters
    sanitized = sanitized.replace("&", "&amp;")
    sanitized = sanitized.replace("<", "&lt;")
    sanitized = sanitized.replace(">", "&gt;")
    sanitized = sanitized.replace("\"", "&quot;")
    sanitized = sanitized.replace("'", "&#x27;")
    
    return sanitized


# utils/notifications.py - Notification utility functions
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from app.config import settings
import logging

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Email notification service"""
    
    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
    
    def send_email(
        self, to_email: str, subject: str, body_text: str, body_html: Optional[str] = None
    ) -> bool:
        """Send an email"""
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = to_email
            
            # Add text part
            part1 = MIMEText(body_text, "plain")
            msg.attach(part1)
            
            # Add HTML part if provided
            if body_html:
                part2 = MIMEText(body_html, "html")
                msg.attach(part2)
            
            # Connect to server and send
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.from_email, to_email, msg.as_string())
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False
    
    def send_permit_expiry_notification(self, to_email: str, permit_number: str, expiry_date: date, days_remaining: int) -> bool:
        """Send permit expiration notification"""
        subject = f"Immigration Permit {permit_number} Expires in {days_remaining} Days"
        
        body_text = f"""
        Dear Permit Holder,
        
        Your immigration permit (Permit Number: {permit_number}) will expire on {expiry_date}.
        You have {days_remaining} days remaining before expiration.
        
        Please log in to your account to review your options for renewal or extension.
        
        Regards,
        USA Immigration System
        """
        
        body_html = f"""
        <html>
        <body>
            <h2>Immigration Permit Expiration Notice</h2>
            <p>Dear Permit Holder,</p>
            <p>Your immigration permit (Permit Number: <strong>{permit_number}</strong>) will expire on <strong>{expiry_date}</strong>.</p>
            <p>You have <strong>{days_remaining} days</strong> remaining before expiration.</p>
            <p>Please <a href="{settings.APPLICATION_URL}/login">log in to your account</a> to review your options for renewal or extension.</p>
            <p>Regards,<br>USA Immigration System</p>
        </body>
        </html>
        """
        
        return self.send_email(to_email, subject, body_text, body_html)


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


# config.py - Application configuration
from pydantic import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings"""
    # Application
    APP_NAME: str = "USA Immigration System"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = ENVIRONMENT == "development"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./immigration.db")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev_secret_key_change_in_production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Email
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.example.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    FROM_EMAIL: str = os.getenv("FROM_EMAIL", "no-reply@immigration.example.com")
    
    # Application URL for links
    APPLICATION_URL: str = os.getenv("APPLICATION_URL", "http://localhost:8000")
    
    class Config:
        env_file = ".env"


settings = Settings()
    
    