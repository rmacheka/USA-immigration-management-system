# create_test_user.py
from ash_project.app import create_app, db
from ash_project.app.models.user import User

app = create_app()
with app.app_context():
    if not User.query.filter_by(username='postgres').first():
        user = User(username='postgres')
        user.set_password('AshLiam2025')  # Ensure this method exists
        db.session.add(user)
        db.session.commit()
        print('Test user created')
    else:
        print('User already exists')