-- immigration_db_backup.sql
-- USA Immigration Management System Database Schema
-- Created for DBU MSITM.6341 Project

BEGIN;

-- Create tables
CREATE TABLE applicants (
    applicant_id SERIAL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    nationality VARCHAR(100) NOT NULL,
    passport_number VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE applications (
    application_id SERIAL PRIMARY KEY,
    applicant_id INTEGER REFERENCES applicants(applicant_id) NOT NULL,
    visa_type VARCHAR(50) NOT NULL,
    case_number VARCHAR(50) UNIQUE NOT NULL,
    application_date DATE NOT NULL,
    status VARCHAR(30) NOT NULL CHECK (status IN ('Pending', 'Approved', 'Denied', 'Under Review')),
    priority_date DATE,
    receipt_number VARCHAR(50),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
    document_id SERIAL PRIMARY KEY,
    application_id INTEGER REFERENCES applications(application_id) NOT NULL,
    document_type VARCHAR(100) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    upload_date DATE NOT NULL DEFAULT CURRENT_DATE,
    verified BOOLEAN DEFAULT FALSE,
    verification_notes TEXT
);

CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('Admin', 'Officer', 'Staff')),
    active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE case_notes (
    note_id SERIAL PRIMARY KEY,
    application_id INTEGER REFERENCES applications(application_id) NOT NULL,
    user_id INTEGER REFERENCES users(user_id) NOT NULL,
    note_content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_applications_status ON applications(status);
CREATE INDEX idx_applications_visa_type ON applications(visa_type);
CREATE INDEX idx_documents_application ON documents(application_id);
CREATE INDEX idx_case_notes_application ON case_notes(application_id);

-- Insert sample data (optional)
INSERT INTO applicants (first_name, last_name, date_of_birth, nationality, passport_number, email)
VALUES 
('Maria', 'Garcia', '1985-06-15', 'Mexico', 'MX12345678', 'maria.garcia@example.com'),
('James', 'Smith', '1990-11-22', 'Canada', 'CA98765432', 'james.smith@example.com');

INSERT INTO applications (applicant_id, visa_type, case_number, application_date, status)
VALUES
(1, 'H1B', 'CSC-2023-1001', '2023-01-15', 'Approved'),
(2, 'L1', 'CSC-2023-1002', '2023-02-20', 'Under Review');

INSERT INTO users (username, password_hash, email, role)
VALUES
('admin', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'admin@immigration.gov', 'Admin'),
('officer1', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'officer1@immigration.gov', 'Officer');

COMMIT;