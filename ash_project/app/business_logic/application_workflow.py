from .permit_processing import PermitProcessor
from app.models import Application

class ApplicationWorkflow:
    def __init__(self, db_session):
        self.db = db_session
    
    def submit_application(self, application_data):
        try:
            # Validate application
            PermitProcessor.validate_application(application_data)
            
            # Create application record
            new_application = Application(**application_data)
            self.db.add(new_application)
            self.db.commit()
            
            # Initiate background checks
            self._initiate_background_checks(new_application.id)
            
            return new_application
        except Exception as e:
            self.db.rollback()
            raise