from datetime import date, timedelta
from app.services import PermitService
from app.models import Permit

def test_permit_expiration_check(db_session):
    # Create test permit expiring yesterday
    expired_permit = Permit(
        permit_number='TEST123',
        permit_type='H1B',
        issue_date=date.today() - timedelta(days=366),
        expiration_date=date.today() - timedelta(days=1),
        status='active',
        applicant_id=1
    )
    db_session.add(expired_permit)
    db_session.commit()
    
    # Check expiration
    permit_service = PermitService(db_session)
    expired_permits = permit_service.get_expired_permits()
    
    assert len(expired_permits) == 1
    assert expired_permits[0].permit_number == 'TEST123'