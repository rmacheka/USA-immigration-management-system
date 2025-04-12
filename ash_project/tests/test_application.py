import unittest
import json
#import os
#from ash_project.app import create_app

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ash_project.app import create_app

from ash_project.app.extensions import db
from ash_project.app.models.application import Application



class ApplicationsTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test application and client"""
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:yourpassword@localhost/test_immigration_db'
        self.client = self.app.test_client()
        
        with self.app.app_context():
            db.create_all()
            # Add test data
            test_app = Application(
                case_number="TEST-123",
                status="Pending"
            )
            db.session.add(test_app)
            db.session.commit()

    def tearDown(self):
        """Clean up after tests"""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_get_application(self):
        """Test GET /api/applications/<id>"""
        response = self.client.get('/api/applications/1')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['case_number'], "TEST-123")

    def test_create_application(self):
        """Test POST /api/applications"""
        new_app = {
            "case_number": "NEW-456",
            "status": "Submitted"
        }
        response = self.client.post(
            '/api/applications',
            data=json.dumps(new_app),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertEqual(data['case_number'], "NEW-456")

    def test_get_nonexistent_application(self):
        """Test GET for non-existent application"""
        response = self.client.get('/api/applications/999')
        self.assertEqual(response.status_code, 404)

if __name__ == '__main__':
    unittest.main()