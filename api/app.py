from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import os
import json
from datetime import datetime
import sys

# Add the root directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.data_validation import validate_phone_number, validate_status, validate_uscis_number
from utils.geocoding import verify_address

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Data file path
DATA_PATH = "data/records.csv"

# Helper function to load data
def load_data():
    try:
        return pd.read_csv(DATA_PATH)
    except FileNotFoundError:
        # Create empty DataFrame with required columns
        return pd.DataFrame(columns=[
            "Name", "Phone", "USCIS Number", "Profession", 
            "Address", "Nationality", "Permit Expiry", "Status"
        ])

# Helper function to save data
def save_data(df):
    # Ensure the data directory exists
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    df.to_csv(DATA_PATH, index=False)

# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/immigrants', methods=['GET'])
def get_immigrants():
    """Get all immigrants or filter by query parameters"""
    df = load_data()
    
    # Handle filtering by query parameters
    filters = request.args.to_dict()
    if filters:
        for key, value in filters.items():
            if key in df.columns:
                df = df[df[key].str.contains(value, case=False, na=False)]
    
    return jsonify(df.to_dict(orient='records'))

@app.route('/api/immigrants', methods=['POST'])
def add_immigrant():
    """Add a new immigrant record"""
    data = request.json
    df = load_data()
    
    # Validate required fields
    required_fields = ["Name", "Phone", "USCIS Number", "Status"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate phone number
    if not validate_phone_number(data["Phone"]):
        return jsonify({"error": "Invalid phone number format"}), 400
    
    # Validate USCIS number
    if not validate_uscis_number(data["USCIS Number"]):
        return jsonify({"error": "Invalid USCIS Number format"}), 400
    
    # Validate status
    if not validate_status(data["Status"]):
        return jsonify({"error": "Invalid status value"}), 400
    
    # Validate address if provided
    if "Address" in data and data["Address"] and not verify_address(data["Address"]):
        return jsonify({"error": "Invalid address, geocoding failed"}), 400
    
    # Add record
    new_record = pd.DataFrame([data])
    df = pd.concat([df, new_record], ignore_index=True)
    save_data(df)
    
    return jsonify({"message": "Immigrant record added successfully", "id": len(df)-1}), 201

@app.route('/api/immigrants/<int:id>', methods=['GET'])
def get_immigrant(id):
    """Get an immigrant by ID"""
    df = load_data()
    if id < 0 or id >= len(df):
        return jsonify({"error": "Immigrant not found"}), 404
    
    return jsonify(df.iloc[id].to_dict())

@app.route('/api/immigrants/<int:id>', methods=['PUT'])
def update_immigrant(id):
    """Update an immigrant record"""
    df = load_data()
    if id < 0 or id >= len(df):
        return jsonify({"error": "Immigrant not found"}), 404
    
    data = request.json
    
    # Validate phone number if provided
    if "Phone" in data and not validate_phone_number(data["Phone"]):
        return jsonify({"error": "Invalid phone number format"}), 400
    
    # Validate USCIS number if provided
    if "USCIS Number" in data and not validate_uscis_number(data["USCIS Number"]):
        return jsonify({"error": "Invalid USCIS Number format"}), 400
    
    # Validate status if provided
    if "Status" in data and not validate_status(data["Status"]):
        return jsonify({"error": "Invalid status value"}), 400
    
    # Validate address if provided
    if "Address" in data and data["Address"] and not verify_address(data["Address"]):
        return jsonify({"error": "Invalid address, geocoding failed"}), 400
    
    # Update record
    for key, value in data.items():
        df.at[id, key] = value
    
    save_data(df)
    return jsonify({"message": "Immigrant record updated successfully"})

@app.route('/api/immigrants/<int:id>', methods=['DELETE'])
def delete_immigrant(id):
    """Delete an immigrant record"""
    df = load_data()
    if id < 0 or id >= len(df):
        return jsonify({"error": "Immigrant not found"}), 404
    
    df = df.drop(id).reset_index(drop=True)
    save_data(df)
    return jsonify({"message": "Immigrant record deleted successfully"})

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get statistical information about immigrants"""
    df = load_data()
    
    if len(df) == 0:
        return jsonify({
            "total": 0,
            "by_status": {},
            "by_nationality": {}
        })
    
    # Get counts by status
    status_counts = df['Status'].value_counts().to_dict()
    
    # Get counts by nationality
    nationality_counts = df['Nationality'].value_counts().to_dict()
    
    return jsonify({
        "total": len(df),
        "by_status": status_counts,
        "by_nationality": nationality_counts
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000) 