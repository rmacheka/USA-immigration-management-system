#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr 12 18:00:51 2025

@author: mz
"""
import pytest
from datetime import date, timedelta
from fastapi.testclient import TestClient
from app.main import app
from app.models import Immigrant, Permit, ContactInfo, Address, EmploymentHistory
from app.database import SessionLocal

client = TestClient(app)

def test_add_immigrant():
    response = client.post("/immigrants/", json={
        "first_name": "Alice",
        "last_name": "Smith",
        "dob": "1990-01-01",
        "nationality": "USA",
        "gender": "Female",
        "passport_number": "ABC123456"
    })
    assert response.status_code == 201
    data = response.json()
    assert data["first_name"] == "Alice"
    assert "id" in data

def test_issue_permit():
    db = SessionLocal()
    immigrant = db.query(Immigrant).first()
    response = client.post("/permits/", json={
        "immigrant_id": immigrant.id,
        "status": "Temporary",
        "issue_date": str(date.today()),
        "expiry_date": str(date.today() + timedelta(days=365)),
        "type": "Work",
        "issuing_authority": "DHS"
    })
    assert response.status_code == 201

def test_update_status():
    db = SessionLocal()
    immigrant = db.query(Immigrant).first()
    response = client.put(f"/immigrants/{immigrant.id}/status", json={"status": "Permanent"})
    assert response.status_code == 200
    assert response.json()["status"] == "Permanent"

def test_expired_permits():
    db = SessionLocal()
    expired_date = date.today() - timedelta(days=1)
    immigrant = db.query(Immigrant).first()
    client.post("/permits/", json={
        "immigrant_id": immigrant.id,
        "status": "Temporary",
        "issue_date": str(date.today() - timedelta(days=365)),
        "expiry_date": str(expired_date),
        "type": "Visitor",
        "issuing_authority": "DHS"
    })
    response = client.get("/permits/expired")
    assert response.status_code == 200
    assert any(permit["expiry_date"] == str(expired_date) for permit in response.json())

def test_bug_reporting():
    response = client.post("/bugs/", json={
        "title": "Permit not updating",
        "description": "The status change does not reflect on the dashboard.",
        "severity": "High"
    })
    assert response.status_code == 201

def test_performance_bulk_add():
    for i in range(100):
        client.post("/immigrants/", json={
            "first_name": f"User{i}",
            "last_name": "LoadTest",
            "dob": "1990-01-01",
            "nationality": "Testland",
            "gender": "Other",
            "passport_number": f"PASS{i}"
        })
    response = client.get("/immigrants/")
    assert response.status_code == 200
    assert len(response.json()) >= 100

def test_api_authentication():
    response = client.get("/secure/data", headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 401

def test_database_consistency():
    db = SessionLocal()
    immigrant = db.query(Immigrant).first()
    contact = db.query(ContactInfo).filter(ContactInfo.immigrant_id == immigrant.id).first()
    address = db.query(Address).filter(Address.immigrant_id == immigrant.id).first()
    assert contact.immigrant_id == address.immigrant_id == immigrant.id

def test_employment_linking():
    db = SessionLocal()
    immigrant = db.query(Immigrant).first()
    job = EmploymentHistory(
        immigrant_id=immigrant.id,
        employer_name="Test Inc",
        position="Developer",
        industry="Tech",
        start_date=date(2021, 1, 1),
        end_date=None,
        salary_range="$70,000-$90,000",
        employment_status="Active"
    )
    db.add(job)
    db.commit()
    assert job.id is not None

def test_export_data():
    response = client.get("/export/immigrants?format=csv")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv"

