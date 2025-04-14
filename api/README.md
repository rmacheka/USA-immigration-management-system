# USA Immigration Management System API

## Overview

This API provides endpoints for managing immigrant records, including CRUD operations, search, filtering, and statistical analysis. It's part of the USA Immigration Management System project.

**Implemented by:** Ade Solanke (API/Integration Specialist)

## Features

- Complete CRUD operations for immigrant records
- Advanced filtering and search capabilities
- Comprehensive data validation
- Statistical analysis of immigration data
- Authentication middleware for secure access
- OpenAPI documentation

## API Endpoints

### Health Check
- `GET /api/health` - Check API operational status

### Immigrant Records
- `GET /api/immigrants` - Get all immigrants with optional filtering
- `GET /api/immigrants/{id}` - Get a specific immigrant by ID
- `POST /api/immigrants` - Create a new immigrant record
- `PUT /api/immigrants/{id}` - Update an existing immigrant record
- `DELETE /api/immigrants/{id}` - Delete an immigrant record

### Statistics
- `GET /api/statistics` - Get statistical information about immigrants

## API Documentation

The API is documented using the OpenAPI Specification (OAS) 3.0. The full documentation can be found in the `openapi.yaml` file.

## Authentication

The API includes a basic authentication middleware using JWT tokens. In the current implementation, this is a placeholder for more comprehensive authentication to be implemented in the future.

## Data Validation

The API includes comprehensive validation for all data inputs, including:
- Phone number format validation
- Status value validation
- USCIS number validation
- Address validation through geocoding

## Error Handling

All endpoints include proper error handling with appropriate HTTP status codes and error messages in the response body.

## Future Improvements

- Implement full JWT authentication
- Add role-based access control
- Expand statistical endpoints
- Add pagination for large result sets
- Implement caching for frequently accessed data

## Usage

To use this API:

1. Make sure the Flask app is running
2. Send HTTP requests to the appropriate endpoints
3. Include the necessary request parameters and body data
4. Handle the responses according to the API documentation

## Dependencies

- Flask
- Flask-CORS
- pandas
- datetime
- json
- geopy 