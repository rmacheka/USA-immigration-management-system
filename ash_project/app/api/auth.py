from flask import request, jsonify
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from app.services.auth_service import AuthService
from app.utils.logger import log

class LoginAPI(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            log.warning("Login attempt with missing credentials")
            return {'message': 'Username and password required'}, 400
        
        auth_result = AuthService.authenticate(username, password)
        if not auth_result:
            return {'message': 'Invalid credentials'}, 401
        
        return jsonify(auth_result)

class RefreshTokenAPI(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = AuthService.refresh_token(current_user)
        if not new_token:
            return {'message': 'Invalid user'}, 401
        
        return jsonify(new_token)

class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'message': f'Hello, user {current_user}'}, 200