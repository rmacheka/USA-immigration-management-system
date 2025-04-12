import pytest
from app import create_app
from app.extensions import db

@pytest.fixture
def app():
    app = create_app(config_class='app.config.TestConfig')
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def db_session(app):
    with app.app_context():
        yield db.session