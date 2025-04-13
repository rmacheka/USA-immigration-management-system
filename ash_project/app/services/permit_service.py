from datetime import date, timedelta, datetime
from typing import List, Optional
from sqlalchemy.exc import SQLAlchemyError

# Use explicit absolute import from ash_project
from ash_project.app.extensions import db
from ash_project.app.models.permit import Permit, PermitStatus, PermitType
# Assuming you have an Applicant model
# from ash_project.app.models.applicant import Applicant 

# Import NotificationService if needed for expiry notifications
# from .notification_services import NotificationService

class PermitService:

    @staticmethod
    def create_permit(
        applicant_id: int,
        permit_number: str,
        permit_type: str, # Should match PermitType enum values
        issue_date: date,
        expiration_date: date,
        status: str = PermitStatus.ACTIVE.value # Default to active? Or pending?
    ) -> Permit:
        """Creates a new permit record."""
        try:
            # Validate permit_type against Enum
            try:
                valid_permit_type = PermitType(permit_type)
            except ValueError:
                raise ValueError(f"Invalid permit_type: {permit_type}")

            # Validate status against Enum
            try:
                valid_status = PermitStatus(status)
            except ValueError:
                raise ValueError(f"Invalid status: {status}")

            # Optional: Check if applicant exists
            # applicant = Applicant.query.get(applicant_id)
            # if not applicant:
            #     raise ValueError(f"Applicant with ID {applicant_id} not found.")

            permit = Permit(
                applicant_id=applicant_id,
                permit_number=permit_number,
                permit_type=valid_permit_type,
                issue_date=issue_date,
                expiration_date=expiration_date,
                status=valid_status,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(permit)
            db.session.commit()
            return permit
        except SQLAlchemyError as e:
            db.session.rollback()
            # Log the error e
            raise ValueError(f"Database error creating permit: {str(e)}")
        except Exception as e:
            db.session.rollback()
            # Log the error e
            raise ValueError(f"Error creating permit: {str(e)}")

    @staticmethod
    def get_permit_by_id(permit_id: int) -> Optional[Permit]:
        """Fetches a permit by its ID."""
        try:
            return Permit.query.get(permit_id)
        except Exception as e:
            # Log the error e
            raise ValueError(f"Error fetching permit {permit_id}: {str(e)}")

    @staticmethod
    def get_expiring_permits(days_threshold: int = 30) -> List[Permit]:
        """Finds permits expiring within the given threshold (in days)."""
        try:
            today = date.today()
            threshold_date = today + timedelta(days=days_threshold)
            return Permit.query.filter(
                Permit.expiration_date <= threshold_date,
                Permit.expiration_date >= today,
                Permit.status == PermitStatus.ACTIVE
            ).all()
        except Exception as e:
            # Log the error e
            raise ValueError(f"Error fetching expiring permits: {str(e)}")

    @staticmethod
    def get_expired_permits() -> List[Permit]:
        """Finds permits whose expiration date has passed."""
        try:
            today = date.today()
            return Permit.query.filter(
                Permit.expiration_date < today,
                Permit.status == PermitStatus.ACTIVE  # Only find active ones that *should* be expired
            ).all()
        except Exception as e:
            # Log the error e
            raise ValueError(f"Error fetching expired permits: {str(e)}")

    @staticmethod
    def update_permit_status(permit_id: int, new_status: str) -> Optional[Permit]:
        """Updates the status of a specific permit."""
        try:
            permit = Permit.query.get(permit_id)
            if not permit:
                return None # Or raise NotFoundException

            # Validate status against Enum
            try:
                valid_status = PermitStatus(new_status)
            except ValueError:
                raise ValueError(f"Invalid new status: {new_status}")

            permit.status = valid_status
            permit.updated_at = datetime.utcnow()
            db.session.commit()
            return permit
        except SQLAlchemyError as e:
            db.session.rollback()
            # Log the error e
            raise ValueError(f"Database error updating permit status: {str(e)}")
        except Exception as e:
            db.session.rollback()
            # Log the error e
            raise ValueError(f"Error updating permit status: {str(e)}")