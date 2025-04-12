from flask import Blueprint
from flask_restful import Api
from .auth import LoginResource, RefreshResource
from .applications import ApplicationResource, ApplicationListResource
from .search import AdvancedSearchResource
from .notifications import NotificationResource

bp = Blueprint('api', __name__)
api = Api(bp)

# Register API resources
api.add_resource(LoginResource, '/auth/login')
api.add_resource(RefreshResource, '/auth/refresh')
api.add_resource(ApplicationListResource, '/applications')
api.add_resource(ApplicationResource, '/applications/<int:application_id>')
api.add_resource(AdvancedSearchResource, '/search/advanced')
api.add_resource(NotificationResource, '/notifications')