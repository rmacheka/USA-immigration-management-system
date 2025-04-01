import sys
from pathlib import Path

# Add the project root to Python's path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(project_root))

# Now import
from app.models.permit import PermitStatus, PermitType

from pydantic import BaseModel
from datetime import datetime
#from app.models.permit import PermitStatus, PermitType

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