from sqlalchemy.orm import Session
from app.models.document import Document, DocumentStatus, DocumentType
from typing import Optional, List
from datetime import datetime

class DocumentService:
    def create_document(
        self,
        db: Session,
        applicant_id: int,
        document_type: DocumentType,
        file_path: str,
        upload_date: datetime,
        status: DocumentStatus = DocumentStatus.PENDING
    ) -> Document:
        """Create a new document"""
        document = Document(
            applicant_id=applicant_id,
            document_type=document_type,
            file_path=file_path,
            upload_date=upload_date,
            status=status
        )
        db.add(document)
        db.commit()
        db.refresh(document)
        return document

    def get_document(self, db: Session, document_id: int) -> Optional[Document]:
        """Get document by ID"""
        return db.query(Document).filter(Document.id == document_id).first()

    def get_documents_by_applicant(self, db: Session, applicant_id: int) -> List[Document]:
        """Get all documents for an applicant"""
        return db.query(Document).filter(Document.applicant_id == applicant_id).all()

    def update_document_status(
        self,
        db: Session,
        document_id: int,
        status: DocumentStatus
    ) -> Optional[Document]:
        """Update document status"""
        document = self.get_document(db, document_id)
        if document:
            document.status = status
            db.commit()
            db.refresh(document)
        return document

    def delete_document(self, db: Session, document_id: int) -> bool:
        """Delete a document"""
        document = self.get_document(db, document_id)
        if document:
            db.delete(document)
            db.commit()
            return True
        return False
