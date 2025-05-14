from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User

jwt = JWTManager()

class AuthService:
    @staticmethod
    def authenticate(username, password):
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            return user
        return None

    @staticmethod
    def generate_token(user):
        additional_claims = {"role": user.role}
        return create_access_token(
            identity=user.id,
            additional_claims=additional_claims
        )

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.get(identity)