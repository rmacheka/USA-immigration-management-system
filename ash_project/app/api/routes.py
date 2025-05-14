from flask import Blueprint, request, jsonify
from ..services import application_service

api_bp = Blueprint('api', __name__)

@api_bp.route('/applications', methods=['POST'])
def create_application():
    data = request.get_json()
    application = application_service.create_application(data)
    return jsonify(application.to_dict()), 201

@api_bp.route('/applications/<int:app_id>', methods=['GET'])
def get_application(app_id):
    application = application_service.get_application(app_id)
    return jsonify(application.to_dict())