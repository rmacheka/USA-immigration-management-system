from pydantic import BaseModel
from datetime import datetime
from app.models.application import ApplicationStatus, ApplicationType

class ApplicationBase(BaseModel):
    applicant_id: int
    application_type: ApplicationType
    submission_date: datetime
    status: ApplicationStatus = ApplicationStatus.PENDING

class ApplicationCreate(ApplicationBase):
    pass

class Application(ApplicationBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True 