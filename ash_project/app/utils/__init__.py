import os
from werkzeug.utils import secure_filename
from flask import current_app

def save_uploaded_file(file, subfolder):
    """Save uploaded file to the appropriate directory"""
    filename = secure_filename(file.filename)
    upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], subfolder)
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)
    return filepath

def validate_uscis_number(number):
    """Validate USCIS number format"""
    return len(number) == 9 and number.isdigit()

def paginate(query, page, per_page):
    """Paginate SQLAlchemy query"""
    return query.paginate(page=page, per_page=per_page, error_out=False)