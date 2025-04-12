from flask import Flask
from .config import Config
from .extensions import db, jwt, migrate, cors
from .utils.logger import init_logger
from .utils.scheduler import init_scheduler
from .api.auth import LoginAPI, RefreshTokenAPI, ProtectedResource
from flask_restful import Api

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Register blueprints
    from .api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    return app
