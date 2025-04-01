from pydantic import BaseModel
from datetime import datetime
from app.models.permit import PermitStatus, PermitType

class PermitBase(BaseModel):
    application_id: int
    permit_type: PermitType
    issue_date: datetime
    expiry_date: datetime
    is_renewable: bool = False
    status: PermitStatus = PermitStatus.ACTIVE

class PermitCreate(PermitBase):
    pass

class Permit(PermitBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True 