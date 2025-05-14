from flask import Blueprint, request
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime

# Use relative imports for services within the same package structure
from ..services.permit_service import PermitService
# Use explicit absolute import from ash_project
from ash_project.app.models.permit import PermitType # Import for validation if needed

# Create a Blueprint for the permit API
permits_bp = Blueprint('permits_api', __name__)
api = Api(permits_bp)

# Helper function to parse dates
def parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        raise ValueError("Date must be in YYYY-MM-DD format")

class PermitListResource(Resource):
    @jwt_required()
    def post(self):
        """Create a new permit"""
        parser = reqparse.RequestParser()
        parser.add_argument('applicant_id', type=int, required=True, help='Applicant ID is required')
        parser.add_argument('permit_number', type=str, required=True, help='Permit number is required')
        parser.add_argument('permit_type', type=str, required=True, help='Permit type is required')
        parser.add_argument('issue_date', type=parse_date, required=True, help='Issue date (YYYY-MM-DD) is required')
        parser.add_argument('expiration_date', type=parse_date, required=True, help='Expiration date (YYYY-MM-DD) is required')
        # Optional: Add status if you want to allow setting it on creation, otherwise use service default
        # parser.add_argument('status', type=str)
        args = parser.parse_args()

        try:
            # Optional: Add authorization check - does the current user have permission?
            # current_user_id = get_jwt_identity()

            new_permit = PermitService.create_permit(
                applicant_id=args['applicant_id'],
                permit_number=args['permit_number'],
                permit_type=args['permit_type'],
                issue_date=args['issue_date'],
                expiration_date=args['expiration_date']
                # status=args.get('status') # Pass status if included in parser
            )
            return {'message': 'Permit created successfully', 'permit_id': new_permit.id}, 201
        except ValueError as e:
            return {'error': str(e)}, 400
        except Exception as e:
            # Log the exception e
            return {'error': 'An unexpected error occurred'}, 500

    @jwt_required()
    def get(self):
        """Get a list of permits (basic implementation)"""
        # TODO: Add filtering, pagination, and proper serialization
        # For now, just returning a placeholder
        # You would typically call a service method like PermitService.get_all_permits()
        return {'message': 'Permit list endpoint - implementation pending'}, 200

# Add the resource to the API
api.add_resource(PermitListResource, '/permits')

# TODO: Add PermitResource for getting/updating/deleting single permits (e.g., /permits/<int:permit_id>)
