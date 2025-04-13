import click
from app import create_app

app = create_app()

@app.cli.command("reset-db")
def reset_db():
    """Drop and recreate all tables"""
    with app.app_context():
        db.drop_all()
        db.create_all()
        click.echo("Database reset complete")