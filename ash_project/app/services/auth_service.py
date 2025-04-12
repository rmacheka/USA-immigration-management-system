from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token, create_refresh_token
from app.models.user import User
from app.extensions import db
from app.utils.logger import log

class AuthService:
    @staticmethod
    def authenticate(username, password):
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            log.warning(f"Failed login attempt for username: {username}")
            return None
        
        if not user.is_active:
            log.warning(f"Inactive user attempt to login: {username}")
            return None
        
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        log.info(f"User {username} logged in successfully")
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role
            }
        }

    @staticmethod
    def refresh_token(user_id):
        user = User.query.get(user_id)
        if not user or not user.is_active:
            return None
        
        new_token = create_access_token(identity=user_id)
        return {'access_token': new_token}