from pydantic import BaseModel
from datetime import datetime
from app.models.applicant import ApplicantStatus

class ApplicantBase(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: datetime
    nationality: str
    passport_number: str
    email: str
    phone_number: str | None = None

class ApplicantCreate(ApplicantBase):
    pass

class Applicant(ApplicantBase):
    id: int
    status: ApplicantStatus
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True 