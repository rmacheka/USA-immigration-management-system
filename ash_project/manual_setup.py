
from app import create_app
from app.extensions import db, migrate

app = create_app()
migrate.init_app(app, db)

if __name__ == '__main__':
    with app.app_context():
        from flask_migrate import upgrade
        upgrade()