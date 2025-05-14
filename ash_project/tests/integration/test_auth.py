import pytest
from app import create_app
from app.extensions import db
from app.models.user import User

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create test user
            user = User(
                username='testuser',
                email='test@example.com',
                role='staff'
            )
            user.set_password('testpass')
            db.session.add(user)
            db.session.commit()
        yield client
        with app.app_context():
            db.drop_all()

def test_login_success(client):
    response = client.post('/api/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_login_failure(client):
    response = client.post('/api/auth/login', json={
        'username': 'testuser',
        'password': 'wrongpass'
    })
    assert response.status_code == 401