from pydantic import BaseModel
from datetime import datetime
from app.models.document import DocumentStatus, DocumentType

class DocumentBase(BaseModel):
    applicant_id: int
    document_type: DocumentType
    file_path: str
    upload_date: datetime
    status: DocumentStatus = DocumentStatus.PENDING

class DocumentCreate(DocumentBase):
    pass

class Document(DocumentBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True 