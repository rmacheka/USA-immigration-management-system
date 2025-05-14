# utils/validators.py - Validation utility functions
import re
from datetime import date
from typing import Optional


def is_valid_email(email: str) -> bool:
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_phone_number(phone: str) -> bool:
    """Validate phone number format (supports international formats)"""
    pattern = r"^\+?[0-9]{10,15}$"
    return bool(re.match(pattern, phone))


def is_valid_passport_number(passport: str) -> bool:
    """Validate passport number format (basic check)"""
    # This is a simplified validation - real validation would depend on country-specific formats
    pattern = r"^[A-Z0-9]{6,12}$"
    return bool(re.match(pattern, passport))


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength"
    """
def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength
    Returns a tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets strength requirements"


def sanitize_input(input_str: Optional[str]) -> Optional[str]:
    """Sanitize input string to prevent injection attacks"""
    if input_str is None:
        return None
    
    # Remove potentially dangerous HTML/script tags
    sanitized = re.sub(r"<[^>]*>", "", input_str)
    
    # Escape special characters
    sanitized = sanitized.replace("&", "&amp;")
    sanitized = sanitized.replace("<", "&lt;")
    sanitized = sanitized.replace(">", "&gt;")
    sanitized = sanitized.replace("\"", "&quot;")
    sanitized = sanitized.replace("'", "&#x27;")
    
    return sanitized

""" if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*()_+=-]", password):
        return False, "Password must contain at least one special character"

    return True, "Password is strong" """


