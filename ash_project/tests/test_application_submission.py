def test_application_submission(client, db_session):
    # Test valid application
    data = {
        'first_name': 'John',
        'last_name': 'Doe',
        'dob': '1990-01-01',
        'email': 'john@example.com',
        'phone': '+1234567890',
        'address': '123 Main St',
        'country': 'US',
        'visa_type': 'work',
        'purpose': 'Employment',
        'duration': 365,
        'passport': (io.BytesIO(b'passport data'), 'passport.jpg'),
        'photo': (io.BytesIO(b'photo data'), 'photo.jpg')
    }
    
    response = client.post(
        '/api/applications',
        data=data,
        content_type='multipart/form-data'
    )
    
    assert response.status_code == 201
    assert 'id' in response.json['data']