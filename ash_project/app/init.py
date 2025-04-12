from flask import Flask
from app.config import Config
from app.extensions import db, jwt, migrate, cors
from app.utils.logger import init_logger
from app.utils.scheduler import init_scheduler
from app.api.auth import LoginAPI, RefreshTokenAPI, ProtectedResource
from flask_restful import Api

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    cors.init_app(app)
    
    # Initialize logger
    init_logger(app)
    
    # Initialize API routes
    api = Api(app)
    api.add_resource(LoginAPI, '/api/auth/login')
    api.add_resource(RefreshTokenAPI, '/api/auth/refresh')
    api.add_resource(ProtectedResource, '/api/protected')
    
    # Initialize scheduler in production
    if not app.debug:
        init_scheduler(app)
    
    return app