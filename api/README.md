# USA Immigration Management System API

API and Integration Components developed by Ade Solanke

## Overview

This module provides a RESTful API and data integration services for the USA Immigration Management System. It includes functionality for:

- Managing immigrant records (CRUD operations)
- Data visualization and geospatial analysis
- PDF report generation
- Email notifications
- Data import/export in multiple formats
- Advanced analytics and forecasting

## Components

### Core API (`app.py`)

The RESTful API built with Flask, providing endpoints for managing immigrant data.

### Data Visualization (`visualization.py`)

Creates data visualizations including:
- Status distribution charts
- Nationality distribution
- Permit expiry timelines
- Status vs. profession heatmaps

### Geospatial Analysis (`geospatial.py`)

Provides geospatial analysis features including:
- US distribution maps
- Immigrant density heatmaps
- Status distribution by state

### Report Generation (`report_generator.py`)

Generates PDF reports including:
- Summary reports
- Detailed reports
- Permit expiry reports
- Status reports

### Notification System (`notifications.py`)

Handles email notifications for:
- Permit expirations
- Status changes
- Weekly summaries

### Data Import/Export (`data_io.py`)

Provides utilities for:
- Importing data from CSV, Excel, JSON, and XML
- Exporting data to CSV, Excel, JSON, and XML
- Data validation

### Advanced Analytics (`analytics.py`)

Implements advanced analytics including:
- Permit expiration forecasting
- Immigrant clustering
- Status transition analysis
- Nationality trend analysis

### Integration (`integration.py`)

Core integration class that ties all components together.

## API Endpoints

### Health Check
- `GET /api/health`: Check API health

### Immigrant Management
- `GET /api/immigrants`: Get all immigrants or filter by query parameters
- `POST /api/immigrants`: Add a new immigrant record
- `GET /api/immigrants/<id>`: Get an immigrant by ID
- `PUT /api/immigrants/<id>`: Update an immigrant record
- `DELETE /api/immigrants/<id>`: Delete an immigrant record

### Statistics
- `GET /api/statistics`: Get statistical information about immigrants

## Getting Started

### Prerequisites

- Python 3.9+
- Dependencies in requirements.txt

### Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the API server:
   ```
   python -m api
   ```

### Configuration

The API can be configured with the following command-line arguments:

- `--host`: Host to run the server on (default: 0.0.0.0)
- `--port`: Port to run the server on (default: 5000)
- `--debug`: Run in debug mode
- `--data-path`: Path to the data file (default: data/records.csv)

Example:
```
python -m api --host 127.0.0.1 --port 8000 --debug --data-path custom/path/records.csv
```

### Environment Variables

- `SMTP_SERVER`: SMTP server for email notifications (default: smtp.gmail.com)
- `SMTP_PORT`: SMTP port (default: 587)
- `SMTP_USERNAME`: SMTP username
- `SMTP_PASSWORD`: SMTP password

## Usage Examples

### API Requests

#### Get all immigrants
```
curl -X GET http://localhost:5000/api/immigrants
```

#### Add a new immigrant
```
curl -X POST http://localhost:5000/api/immigrants \
  -H "Content-Type: application/json" \
  -d '{
    "Name": "John Doe",
    "Phone": "123-456-7890",
    "USCIS Number": "123456789",
    "Profession": "Engineer",
    "Address": "123 Main St, New York, NY",
    "Nationality": "Canadian",
    "Permit Expiry": "2024-12-31",
    "Status": "Temporary"
  }'
```

#### Get statistics
```
curl -X GET http://localhost:5000/api/statistics
```

## Integration with Frontend

The API is designed to work with the frontend components developed by the frontend team. The API follows a RESTful design pattern for easy integration.

## Development

### Code Structure

```
api/
├── __main__.py         # Entry point
├── app.py              # Flask API
├── integration.py      # Main integration
├── analytics.py        # Advanced analytics
├── data_io.py          # Data import/export
├── geospatial.py       # Geospatial analysis
├── notifications.py    # Email notifications
├── report_generator.py # PDF report generation
├── visualization.py    # Data visualization
└── README.md           # This file
```

### Adding New Features

1. Implement the feature in the appropriate module
2. Update the integration class in `integration.py`
3. Add API endpoints in `app.py` if needed

## License

This project is part of the USA Immigration Management System group project. 