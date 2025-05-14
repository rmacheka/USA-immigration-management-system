# USA Immigration Management System - Backend

## Table of Contents
1. [Setup Instructions](#setup-instructions)
2. [Architecture Overview](#architecture-overview)
3. [API Documentation](#api-documentation)
4. [Testing Instructions](#testing-instructions)
5. [Deployment](#deployment)

## Tools Used:

Python (same version used in development)

PostgreSQL/MySQL (or SQLite for quick testing)

Postman/Insomnia (API testing)

VS Code/PyCharm (IDE)

## Setup Instructions

### Prerequisites
- Python 3.9+
- PostgreSQL 12+
- Redis (for caching and background tasks)
- Node.js (for API documentation generation)

### Installation
```bash
# Clone the repository
git clone https://github.com/your-repo/immigration-backend.git
cd immigration-backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration


Database Setup
# Create database (ensure PostgreSQL is running)
createdb immigration_system
# Run migrations
flask db upgrade

Running the Application
# Development mode
flask run --debug
# Production mode (using Gunicorn)
gunicorn -w 4 -b :5000 wsgi:app


Architecture Overview
Core Components
Copy
backend/
├── app/
│   ├── api/               # API endpoints and routes
│   ├── models/            # Database models
│   ├── services/          # Business logic
│   ├── utils/             # Helper functions
│   ├── __init__.py        # Application factory
│   └── config.py          # Configuration settings
├── tests/                 # Unit and integration tests
├── migrations/            # Database migration scripts
└── requirements.txt       # Dependencies


1. Core Business Logic Implementation
Objective
Develop the foundational business rules and workflows that govern the immigration management processes.

Implementation Plan
File Structure:
/app
    /business_logic
        __init__.py
        permit_processing.py
        application_workflow.py
        status_tracking.py
        reporting.py


2. SQLAlchemy ORM Models
Objective
Implementing database models that mirror the PostgreSQL schema designed by Julie.

Implementation Plan
File Structure:
/app
    /models
        __init__.py
        user.py
        permit.py
        application.py
        document.py


3. Service Layer Components
Objective
Create an abstraction layer between business logic and data access.

Implementation Plan
File Structure:
/app
    /services
        __init__.py
        permit_service.py
        applicant_service.py
        document_service.py
        auth_service.py



4. Permit Tracking & Expiration System
Objective
Implement automated tracking and status updates for expiring permits.

Implementation Plan
Implementation Files:
/app
    /utils
        permit_tracker.py
    /tasks
        expiration_check.py



5. Authentication & Authorization System
Objective
Implement secure user authentication and role-based access control.

Implementation Plan
Implementation Files:
/app
    /auth
        __init__.py
        core.py
        decorators.py
        schemas.py



6. Error Handling & Logging System
Objective
Implement comprehensive error handling and logging across the application.

Implementation Plan
Implementation Files:
/app
    /errors
        __init__.py
        handlers.py
        exceptions.py
    /utils
        logger.py



7. Utility Functions
Objective
Create reusable utility functions for common operations.

Implementation Plan
File Structure:
/app
    /utils
        __init__.py
        validation.py
        date_helpers.py
        file_processing.py
        api_helpers.py



8. Unit Testing Implementation
Objective
Develop comprehensive unit tests for all backend functionality.

Implementation Plan
File Structure:
/tests
    /unit
        __init__.py
        test_models.py
        test_services.py
        test_auth.py
        test_utils.py
    conftest.py



I aligned my SQLAlchemy models with Julie's database schema.

Database Schema Reconciliation
1. Analyzed Julie's Data Structure

Name

Phone

USCIS Number (9 digits)

Profession

Address

Nationality

Permit Expiry

Status (Permanent/Temporary/Expired/Illegal)

2. Updated SQLAlchemy Models
File: app/models/applicant.py



Key Technologies
Flask: Web framework

SQLAlchemy: ORM for database operations

Flask-RESTful: API resource management

JWT: Authentication system

Celery: Background task processing

Alembic: Database migrations

API Documentation
Interactive Documentation
Swagger UI: http://localhost:5000/api/docs

Redoc: http://localhost:5000/api/redoc



virtual environment 

All dependencies listed in ash_project/requirement.txt have been successfully installed in the venv virtual environment.
.\venv\Scripts\Activate.ps1 in PowerShell

Locating the main Python file:
Based on the file listing I saw earlier, there is a main.py file located directly in the root directory of your project (/c%3A/Users/Rue/OneDrive%20-%20Dallas%20Baptist%20University/Documents/GitHub/MSITM.6341/Project/USA-immigration-management-system)

Getting the project on GitHub:
It looks like you already have a Git repository initialized in your project directory (I see a .git folder). Let's check if a remote repository (like one on GitHub) is already configured.
I'll run git remote -v to check.
