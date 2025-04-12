from datetime import datetime, timedelta

def validate_date_format(date_str, format='%Y-%m-%d'):
    """Validate date string format"""
    try:
        datetime.strptime(date_str, format)
        return True
    except ValueError:
        return False

def calculate_days_remaining(target_date):
    """Calculate days remaining until target date"""
    return (target_date - datetime.now().date()).days