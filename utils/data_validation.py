import re

def validate_phone_number(phone):
    return re.match(r"^\+1\d{10}$", phone) is not None