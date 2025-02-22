import re

def validate_phone_number(phone):
    return re.match(r"^\+1\d{10}$", phone) is not None

def validate_uscis_number(uscis):
    """Validate a USCIS number format: 9-digit numeric"""
    return re.match(r"^\d{9}$", uscis) is not None

def validate_status(status):
    """Validate immigration status (common statuses like 'Permanent Resident', 'Student Visa', 'Work Visa', etc.)"""
    allowed_statuses = {'Permanent Resident', 'Student Visa', 'Work Visa', 'Refugee', 'Asylum Seeker', 'Visitor'}
    return status in allowed_statuses
