from datetime import datetime
from typing import List, Optional
from sqlalchemy import or_

from ash_project.app.extensions import db
from ash_project.app.models.application import Application, ApplicationStatus
from ash_project.app.models.notification import Notification
from .notification_services import NotificationService


class ApplicationService:
    @staticmethod
    def create_application(
        user_id: int,
        first_name: str,
        last_name: str,
        dob: datetime,
        email: str,
        phone: str,
        address: str,
        country: str,
        visa_type: str,
        purpose: str,
        duration_days: int,
        passport_path: str,
        photo_path: str,
        gender: Optional[str] = None
    ) -> Application:
        """
        Create a new immigration application
        Returns: Application object
        """
        try:
            application = Application(
                user_id=user_id,
                first_name=first_name,
                last_name=last_name,
                dob=dob,
                gender=gender,
                email=email,
                phone=phone,
                address=address,
                country=country,
                visa_type=visa_type,
                purpose=purpose,
                duration_days=duration_days,
                passport_path=passport_path,
                photo_path=photo_path,
                status='submitted',
                created_at=datetime.utcnow()
            )
            
            db.session.add(application)
            db.session.commit()
            
            NotificationService.create_notification(
                user_id=user_id,
                message=f"Your application {application.id} has been submitted",
                notification_type='application_submitted'
            )
            
            return application
            
        except Exception as e:
            db.session.rollback()
            raise ValueError(f"Error creating application: {str(e)}")

    @staticmethod
    def search_applications(
        search_term: Optional[str] = None,
        status: Optional[str] = None,
        visa_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        country: Optional[str] = None
    ) -> List[Application]:
        """
        Search applications with advanced filters
        Returns: List of Application objects
        """
        try:
            query = Application.query

            if search_term:
                query = query.filter(
                    or_(
                        Application.first_name.ilike(f'%{search_term}%'),
                        Application.last_name.ilike(f'%{search_term}%'),
                        Application.id.ilike(f'%{search_term}%')
                    )
                )

            if status:
                query = query.filter(Application.status == status)
                
            if visa_type:
                query = query.filter(Application.visa_type == visa_type)
                
            if start_date and end_date:
                query = query.filter(Application.created_at.between(start_date, end_date))
                
            if country:
                query = query.filter(Application.country == country)

            return query.order_by(Application.created_at.desc()).all()
            
        except Exception as e:
            raise ValueError(f"Error searching applications: {str(e)}")

    @staticmethod
    def get_application_by_id(application_id: int) -> Optional[Application]:
        """Get single application by ID"""
        try:
            return Application.query.get(application_id)
        except Exception as e:
            raise ValueError(f"Error fetching application: {str(e)}")