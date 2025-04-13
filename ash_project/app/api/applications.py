from flask import request
from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
# Use explicit absolute imports from ash_project
from ash_project.app.models import Application, Document
#from ..services import ApplicationService # Keep ApplicationService commented for now
from ash_project.app.utils import save_uploaded_file

class ApplicationListResource(Resource):
    @jwt_required()
    def get(self):
        """Get all applications"""
    #    return ApplicationService.get_all_applications(get_jwt_identity())

    @jwt_required()
    def post(self):
        """Create new application"""
        parser = reqparse.RequestParser()
        parser.add_argument('first_name', type=str, required=True)
        parser.add_argument('last_name', type=str, required=True)
        # Add all other fields...
        args = parser.parse_args()

        try:
            # Handle file uploads
            passport = request.files['passport']
            photo = request.files['photo']
            
            passport_path = save_uploaded_file(passport, 'passports')
            photo_path = save_uploaded_file(photo, 'photos')
            
            # Create application
            application = ApplicationService.create_application(
                user_id=get_jwt_identity(),
                first_name=args['first_name'],
                last_name=args['last_name'],
                # Include all other fields...
                passport_path=passport_path,
                photo_path=photo_path
            )
            
            return {'message': 'Application created', 'id': application.id}, 201
        except Exception as e:
            return {'error': str(e)}, 400

class ApplicationResource(Resource):
    @jwt_required()
    def get(self, application_id):
        """Get application details"""
        return ApplicationService.get_application(
            application_id, 
            get_jwt_identity()
        )