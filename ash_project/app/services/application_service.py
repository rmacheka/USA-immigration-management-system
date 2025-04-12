#.\venv\Scripts\activate

from datetime import datetime
from app.models import Application, ApplicationStatus, Notification
from app.extensions import db
from .notification_services import NotificationService

class ApplicationService:
    @staticmethod
    def create_application(user_id, first_name, last_name, dob, email, phone,
                         address, country, visa_type, purpose, duration_days,
                         passport_path, photo_path, gender=None):
        """Create a new immigration application"""
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
            photo_path=photo_path
        )
        
        db.session.add(application)
        db.session.commit()
        
        # Create notification
        NotificationService.create_notification(
            user_id=user_id,
            message=f"Your application {application.id} has been submitted",
            notification_type='application_submitted'
        )
        
        return application

    @staticmethod
    def search_applications(query=None, status=None, visa_type=None,
                          start_date=None, end_date=None, country=None):
        """Search applications with filters"""
        query = Application.query
        
        if query:
            query = query.filter(
                db.or_(
                    Application.first_name.ilike(f'%{query}%'),
                    Application.last_name.ilike(f'%{query}%'),
                    Application.id.ilike(f'%{query}%')
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
            
        return query.all()