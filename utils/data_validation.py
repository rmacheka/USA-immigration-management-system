"""
USA Immigration Management System - Data Validation Utilities
Implemented by: RU (Backend Developer)
This module provides validation functions for phone numbers, USCIS numbers, and status values.
"""

import re

def validate_phone_number(phone_number: str) -> bool:
    """Validate a phone number using a regex pattern."""
    # Validate phone number format (e.g. 123-456-7890)
    pattern = r'^\d{3}-\d{3}-\d{4}$'
    return bool(re.match(pattern, phone_number))

def validate_uscis_number(uscis_number: str) -> bool:
    """Validate a USCIS number (9 digits)."""
    # USCIS numbers should be exactly 9 digits
    pattern = r'^\d{9}$'
    return bool(re.match(pattern, uscis_number))

def validate_status(status: str) -> bool:
    """Validate immigration status value."""
    # Status should be one of: Permanent, Temporary, Expired, Illegal
    valid_statuses = ['Permanent', 'Temporary', 'Expired', 'Illegal']
    return status in valid_statuses