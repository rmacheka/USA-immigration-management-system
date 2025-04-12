def test_applicant_model_matches_schema(db_session):
    # Verify all expected columns exist
    expected_columns = {
        'name', 'phone', 'uscis_number', 
        'profession', 'address', 'nationality'
    }
    actual_columns = {c.name for c in Applicant.__table__.columns}
    assert expected_columns.issubset(actual_columns)

def test_permit_status_values(db_session):
    # Verify only permitted status values are allowed
    from sqlalchemy.exc import IntegrityError
    from app.models import PermitStatus
    
    permit = Permit(
        applicant_id=1,
        expiry_date='2023-12-31',
        status='Invalid'  # Should raise error
    )
    db_session.add(permit)
    
    with pytest.raises(IntegrityError):
        db_session.commit()