# utils/date_utils.py - Date utility functions
from datetime import date, datetime, timedelta
from typing import Tuple, Optional


def calculate_date_difference(start_date: date, end_date: date) -> int:
    """Calculate the difference in days between two dates"""
    return (end_date - start_date).days


def calculate_visa_duration(months: int) -> Tuple[date, date]:
    """Calculate issue and expiry dates for a visa with specified duration in months"""
    issue_date = date.today()
    expiry_date = issue_date + timedelta(days=30 * months)
    return issue_date, expiry_date


def is_valid_birth_date(birth_date: date) -> bool:
    """Check if a birth date is valid (not in future and person is at least 1 year old)"""
    today = date.today()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    return birth_date < today and age >= 1


def is_date_in_range(check_date: date, start_date: date, end_date: date) -> bool:
    """Check if a date is within a specified range"""
    return start_date <= check_date <= end_date


def format_date(date_obj: date, format_str: str = "%Y-%m-%d") -> str:
    """Format a date object as a string"""
    return date_obj.strftime(format_str)


def parse_date(date_str: str, format_str: str = "%Y-%m-%d") -> Optional[date]:
    """Parse a date string into a date object"""
    try:
        return datetime.strptime(date_str, format_str).date()
    except ValueError:
        return None


