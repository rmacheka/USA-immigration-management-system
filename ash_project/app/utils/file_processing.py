import os
from werkzeug.utils import secure_filename
from flask import current_app

def save_uploaded_file(file_data, subfolder):
    """Save uploaded file to the appropriate directory"""
    try:
        # Ensure upload folder exists
        upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], subfolder)
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate secure filename
        filename = secure_filename(file_data.filename)
        filepath = os.path.join(upload_folder, filename)
        
        # Save file
        file_data.save(filepath)
        
        return filepath
        
    except Exception as e:
        current_app.logger.error(f"Error saving file: {str(e)}")
        raise