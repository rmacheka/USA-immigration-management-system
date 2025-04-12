from app.models import PermitType
from datetime import timedelta

# Define permit durations (example values)
PERMIT_DURATIONS = {
    PermitType.TOURIST.value: 90, 
    PermitType.WORK.value: 365 * 2,
    PermitType.STUDENT.value: 365,
    # Add other permit types and durations
}

class PermitProcessor:
    @staticmethod
    def validate_application(application_data):
        """Validate all application requirements are met"""
        required_fields = ['applicant_id', 'permit_type', 'supporting_docs']
        if not all(field in application_data for field in required_fields):
            raise ValueError("Missing required application fields")
        
        # Validate against PermitType enum values
        if application_data['permit_type'] not in [pt.value for pt in PermitType]:
            raise ValueError("Invalid permit type specified")

    @staticmethod
    def calculate_expiration(issue_date, permit_type):
        """Calculate expiration date based on permit type"""
        # Assuming permit_type is the string value from the enum
        duration = PERMIT_DURATIONS.get(permit_type, 365) # Use the defined dictionary
        return issue_date + timedelta(days=duration)