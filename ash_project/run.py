#   .\venv\Scripts\activate

"""import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv() 

#from ash_project.app import create_app
from app import create_app # Use relative import

# Create the Flask application instance
app = create_app()

if __name__ == '__main__':
    # Run the application
    app.run(host=os.getenv('FLASK_HOST', '0.0.0.0'),
            port=int(os.getenv('FLASK_PORT', 5000)),
            debug=os.getenv('FLASK_DEBUG', True))"""
    
# run.py
from app import create_app

app = create_app()  # This line is critical

if __name__ == "__main__":
    app.run(debug=True)

