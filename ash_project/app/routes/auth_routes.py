from flask import request, jsonify, Blueprint, current_app
from flask_jwt_extended import create_access_token
from ash_project.app.models.user import User

# Create a Blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Invalid request format"}), 400
            
        user = User.query.filter_by(username=data['username']).first()
        
        if not user:
            current_app.logger.error(f"User not found: {data['username']}")
            return jsonify({"error": "Invalid credentials"}), 401
            
        if not user.check_password(data['password']):
            current_app.logger.error(f"Password mismatch for user: {data['username']}")
            return jsonify({"error": "Invalid credentials"}), 401
            
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500