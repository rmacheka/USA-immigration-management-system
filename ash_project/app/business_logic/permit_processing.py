class PermitProcessor:
    @staticmethod
    def validate_application(application_data):
        """Validate all application requirements are met"""
        required_fields = ['applicant_id', 'permit_type', 'supporting_docs']
        if not all(field in application_data for field in required_fields):
            raise ValueError("Missing required application fields")
        
        if application_data['permit_type'] not in PERMIT_TYPES:
            raise ValueError("Invalid permit type specified")

    @staticmethod
    def calculate_expiration(issue_date, permit_type):
        """Calculate expiration date based on permit type"""
        duration = PERMIT_DURATIONS.get(permit_type, 365)
        return issue_date + timedelta(days=duration)