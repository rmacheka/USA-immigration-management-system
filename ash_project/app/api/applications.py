from flask_restful import Resource, reqparse
from werkzeug.utils import secure_filename
from app.services import ApplicationService
from app.utils.file_processing import save_uploaded_file

class ApplicationAPI(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self._init_parser()

    def _init_parser(self):
        self.parser.add_argument('first_name', type=str, required=True)
        self.parser.add_argument('last_name', type=str, required=True)
        self.parser.add_argument('dob', type=str, required=True)
        self.parser.add_argument('gender', type=str)
        self.parser.add_argument('email', type=str, required=True)
        self.parser.add_argument('phone', type=str, required=True)
        self.parser.add_argument('address', type=str, required=True)
        self.parser.add_argument('country', type=str, required=True)
        self.parser.add_argument('visa_type', type=str, required=True)
        self.parser.add_argument('purpose', type=str, required=True)
        self.parser.add_argument('duration', type=int, required=True)
        self.parser.add_argument('passport', type=str, required=True)
        self.parser.add_argument('photo', type=str, required=True)
        self.parser.add_argument('additional_docs', type=list, location='json')

    def post(self):
        """Submit new application"""
        args = self.parser.parse_args()
        
        try:
            # Process file uploads
            passport_path = save_uploaded_file(args['passport'], 'passports')
            photo_path = save_uploaded_file(args['photo'], 'photos')
            
            # Create application
            application = ApplicationService.create_application(
                first_name=args['first_name'],
                last_name=args['last_name'],
                dob=args['dob'],
                gender=args['gender'],
                email=args['email'],
                phone=args['phone'],
                address=args['address'],
                country=args['country'],
                visa_type=args['visa_type'],
                purpose=args['purpose'],
                duration=args['duration'],
                passport_path=passport_path,
                photo_path=photo_path,
                additional_docs=args['additional_docs']
            )
            
            return {'message': 'Application submitted', 'id': application.id}, 201
        
        except Exception as e:
            return {'error': str(e)}, 400