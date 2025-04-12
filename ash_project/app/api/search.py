from flask_restful import Resource, reqparse
from app.services import ApplicationService
from app.utils import paginate
from flask_jwt_extended import jwt_required, get_jwt_identity

class AdvancedSearchAPI(Resource):
    def __init__(self):
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('query', type=str, location='json')
        self.parser.add_argument('application_types', type=list, location='json')
        self.parser.add_argument('statuses', type=list, location='json')
        self.parser.add_argument('start_date', type=str, location='json')
        self.parser.add_argument('end_date', type=str, location='json')
        self.parser.add_argument('country', type=str, location='json')
        self.parser.add_argument('page', type=int, default=1)
        self.parser.add_argument('per_page', type=int, default=10)

    def post(self):
        """Handle advanced search with filters"""
        args = self.parser.parse_args()
        
        results = ApplicationService.search_applications(
            query=args['query'],
            application_types=args['application_types'],
            statuses=args['statuses'],
            start_date=args['start_date'],
            end_date=args['end_date'],
            country=args['country']
        )
        
        return paginate(results, args['page'], args['per_page'])

class SearchHistoryAPI(Resource):
    @jwt_required()
    def get(self):
        """Get user's search history"""
        user_id = get_jwt_identity()
        return ApplicationService.get_search_history(user_id)