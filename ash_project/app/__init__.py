# ash_project/app/__init__.py
from flask import Flask
from dotenv import load_dotenv
from .extensions import db, migrate, cors, jwt
from .api import bp as api_bp
from .utils.scheduler import init_scheduler
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)


def create_app(config_class=None):
    app = Flask(__name__)

    # Load config (keep your existing configuration code)
    load_dotenv()
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI=f'postgresql://{os.getenv("POSTGRES_USER")}:{os.getenv("POSTGRES_PASSWORD")}@{os.getenv("POSTGRES_HOST")}/{os.getenv("POSTGRES_DB")}',
        

        #app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "my-super-secure-jwt-key")
        # Add JWT configuration here
        JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "my-super-secure-jwt-key"),
        # ... keep other configs ...
    )

    # Initialize extensions (keep your existing code)
    db.init_app(app)
    migrate.init_app(app)
    cors.init_app(app)
    jwt.init_app(app)
    # ... other extensions ...

    # Import models (NEW LOCATION - JUST IMPORTS, NO db.create_all())
    with app.app_context():
        from .models.applicant import Applicant  # Must be first
        from .models.user import User
        from .models.permit import Permit
        from .models.application import Application
        # ... other models ...

    # Register blueprints (keep your existing code)
    app.register_blueprint(api_bp, url_prefix='/api')

    # Add CLI command for database initialization (NEW)
    @app.cli.command("init-db")
    def init_db():
        """Initialize the database"""
        with app.app_context():
            db.create_all()
            app.logger.info("Database tables created")

    # Add basic routes back
    @app.route('/')
    def index():
        return "Immigration Management System API (PostgreSQL)"

    @app.route('/health')
    def health_check():
        return "OK", 200

    return app


