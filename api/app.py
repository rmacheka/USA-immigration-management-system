"""
USA Immigration Management System - RESTful API
Implemented by: Ade Solanke (API/Integration Specialist)

This API provides endpoints for managing immigration data, including:
- CRUD operations for immigrant records
- Search and filtering capabilities
- Statistical analysis and reporting
- Authentication and authorization
"""

from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import pandas as pd
import os
import json
from datetime import datetime
import sys
from functools import wraps

# Add the root directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.data_validation import validate_phone_number, validate_status, validate_uscis_number
from utils.geocoding import verify_address

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load data
data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
records_path = os.path.join(data_dir, 'records.csv')

# Validation helper functions
def validate_immigrant_data(data):
    """
    Validate immigrant data against required fields and formats.
    
    Args:
        data (dict): The immigrant data to validate
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    required_fields = ['FirstName', 'LastName', 'Status', 'Country', 'Address', 'Phone']
    
    # Check for required fields
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
    
    # Validate phone number
    if not validate_phone_number(data['Phone']):
        return False, "Phone number must be in format: 123-456-7890"
    
    # Validate status
    if not validate_status(data['Status']):
        return False, "Status must be one of: Permanent, Temporary, Expired, Illegal"
    
    # Validate USCIS number if provided
    if 'USCIS_Number' in data and data['USCIS_Number'] and not validate_uscis_number(data['USCIS_Number']):
        return False, "USCIS Number must be exactly 9 digits"
    
    # Validate address
    if not verify_address(data['Address']):
        return False, "Invalid address"
    
    return True, ""

# Authentication middleware (to be implemented with JWT)
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # This is a placeholder for actual JWT authentication
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            # For now, allow requests without auth for testing
            # In production, this would return 401
            pass
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify API is operational"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/immigrants', methods=['GET'])
@requires_auth
def get_immigrants():
    """
    Get all immigrants with optional filtering
    
    Query Parameters:
        status (str): Filter by immigration status
        country (str): Filter by country of origin
        
    Returns:
        JSON list of immigrant records
    """
    try:
        df = pd.read_csv(records_path)
        
        # Apply filters if provided
        status = request.args.get('status')
        if status:
            df = df[df['Status'] == status]
            
        country = request.args.get('country')
        if country:
            df = df[df['Country'] == country]
        
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/immigrants/<immigrant_id>', methods=['GET'])
@requires_auth
def get_immigrant(immigrant_id):
    """
    Get a specific immigrant by ID
    
    Path Parameters:
        immigrant_id (str): The ID of the immigrant to retrieve
        
    Returns:
        JSON object of immigrant record
    """
    try:
        df = pd.read_csv(records_path)
        immigrant = df[df['ID'] == immigrant_id]
        
        if immigrant.empty:
            return jsonify({'error': 'Immigrant not found'}), 404
            
        return jsonify(immigrant.iloc[0].to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/immigrants', methods=['POST'])
@requires_auth
def create_immigrant():
    """
    Create a new immigrant record
    
    Request Body:
        JSON object with immigrant details
        
    Returns:
        JSON object of the created immigrant record
    """
    try:
        data = request.json
        
        # Validate data
        is_valid, error_message = validate_immigrant_data(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400
        
        df = pd.read_csv(records_path)
        
        # Generate ID and add timestamp
        data['ID'] = f"IMM{len(df) + 1:06d}"
        data['DateAdded'] = datetime.now().strftime('%Y-%m-%d')
        
        # Add to dataframe and save
        df = df.append(data, ignore_index=True)
        df.to_csv(records_path, index=False)
        
        return jsonify(data), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/immigrants/<immigrant_id>', methods=['PUT'])
@requires_auth
def update_immigrant(immigrant_id):
    """
    Update an existing immigrant record
    
    Path Parameters:
        immigrant_id (str): The ID of the immigrant to update
        
    Request Body:
        JSON object with updated immigrant details
        
    Returns:
        JSON object of the updated immigrant record
    """
    try:
        data = request.json
        
        # Validate data
        is_valid, error_message = validate_immigrant_data(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400
        
        df = pd.read_csv(records_path)
        immigrant_index = df[df['ID'] == immigrant_id].index
        
        if len(immigrant_index) == 0:
            return jsonify({'error': 'Immigrant not found'}), 404
            
        # Update record
        for key, value in data.items():
            df.loc[immigrant_index[0], key] = value
            
        # Save updated data
        df.to_csv(records_path, index=False)
        
        return jsonify(df.loc[immigrant_index[0]].to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/immigrants/<immigrant_id>', methods=['DELETE'])
@requires_auth
def delete_immigrant(immigrant_id):
    """
    Delete an immigrant record
    
    Path Parameters:
        immigrant_id (str): The ID of the immigrant to delete
        
    Returns:
        JSON confirmation message
    """
    try:
        df = pd.read_csv(records_path)
        immigrant_index = df[df['ID'] == immigrant_id].index
        
        if len(immigrant_index) == 0:
            return jsonify({'error': 'Immigrant not found'}), 404
            
        # Delete record
        df = df.drop(immigrant_index[0])
        df.to_csv(records_path, index=False)
        
        return jsonify({'message': f'Immigrant {immigrant_id} deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
@requires_auth
def get_statistics():
    """
    Get statistical information about immigrants
    
    Returns:
        JSON object with various statistics
    """
    try:
        df = pd.read_csv(records_path)
        
        # Calculate statistics
        stats = {
            'total_immigrants': len(df),
            'by_status': df['Status'].value_counts().to_dict(),
            'by_country': df['Country'].value_counts().to_dict(),
            'recent_additions': len(df[pd.to_datetime(df['DateAdded']) > (datetime.now() - pd.Timedelta(days=30))])
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 