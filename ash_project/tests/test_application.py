from datetime import date, timedelta
from app.models import Application
from app.services import ApplicationService

def test_create_application(db_session):
    app_data = {
        'user_id': 1,
        'first_name': 'John',
        'last_name': 'Doe',
        'dob': date(1990, 1, 1),
        'email': 'john@example.com',
        'phone': '+1234567890',
        'address': '123 Main St',
        'country': 'US',
        'visa_type': 'work',
        'purpose': 'Employment',
        'duration_days': 365,
        'passport_path': 'passports/john.jpg',
        'photo_path': 'photos/john.jpg'
    }
    
    application = ApplicationService.create_application(**app_data)
    assert application.id is not None
    assert application.full_name == 'John Doe'