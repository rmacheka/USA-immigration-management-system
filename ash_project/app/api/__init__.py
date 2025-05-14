from flask import Blueprint
from flask_restful import Api

# Import all Resources
from .auth import LoginResource, RefreshResource 
from .applications import ApplicationResource, ApplicationListResource
from .permits import PermitListResource
from .search import AdvancedSearchAPI
from .notifications import NotificationAPI, NotificationReadAPI

# Create the single API blueprint and the Flask-RESTful Api object
bp = Blueprint('api', __name__)
api = Api(bp)

# Register API resources to the central Api object
api.add_resource(LoginResource, '/auth/login')
api.add_resource(RefreshResource, '/auth/refresh')
api.add_resource(PermitListResource, '/permits') # Added permits resource
api.add_resource(ApplicationListResource, '/applications')
api.add_resource(ApplicationResource, '/applications/<int:application_id>')
api.add_resource(AdvancedSearchAPI, '/search/advanced')
api.add_resource(NotificationAPI, '/notifications')
api.add_resource(NotificationReadAPI, '/notifications/<int:notification_id>/read') # Added route for marking as read

# No need to import auth_bp or permits_bp here