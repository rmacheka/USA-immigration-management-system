class ApplicationService:
    @staticmethod
    def search_applications(query=None, application_types=None, statuses=None,
                          start_date=None, end_date=None, country=None):
        """Search applications with multiple filters"""
        query = db.session.query(Application)
        
        if query:
            query = query.filter(
                or_(
                    Application.full_name.ilike(f'%{query}%'),
                    Application.uscis_number.ilike(f'%{query}%'),
                    Application.id.ilike(f'%{query}%')
                )
            )
        
        if application_types:
            query = query.filter(Application.visa_type.in_(application_types))
            
        if statuses:
            query = query.filter(Application.status.in_(statuses))
            
        if start_date and end_date:
            query = query.filter(Application.created_at.between(start_date, end_date))
            
        if country:
            query = query.filter(Application.country == country)
            
        return query.all()
    
    @staticmethod
    def get_search_history(user_id):
        """Retrieve user's saved search history"""
        return SearchHistory.query.filter_by(user_id=user_id)\
            .order_by(SearchHistory.created_at.desc())\
            .limit(10)\
            .all()
    
    @staticmethod
    def create_application(first_name, last_name, dob, email, phone, address,
                         country, visa_type, purpose, duration, passport_path,
                         photo_path, gender=None, additional_docs=None):
        """Create a new immigration application"""
        try:
            # Validate required fields
            if not all([first_name, last_name, dob, email, phone, address, 
                       country, visa_type, purpose, duration, passport_path, 
                       photo_path]):
                raise ValueError("Missing required fields")
            
            # Create application record
            application = Application(
                first_name=first_name,
                last_name=last_name,
                dob=dob,
                gender=gender,
                email=email,
                phone=phone,
                address=address,
                country=country,
                visa_type=visa_type,
                purpose=purpose,
                duration_days=duration,
                passport_path=passport_path,
                photo_path=photo_path,
                status='pending'
            )
            
            db.session.add(application)
            db.session.flush()  # Get the application ID
            
            # Save additional documents if any
            if additional_docs:
                for doc in additional_docs:
                    doc_path = save_uploaded_file(doc, 'additional_docs')
                    document = ApplicationDocument(
                        application_id=application.id,
                        document_type='additional',
                        file_path=doc_path
                    )
                    db.session.add(document)
            
            db.session.commit()
            
            # Trigger notification
            NotificationService.create_notification(
                user_id=None,  # System notification
                message=f"New application submitted: {application.full_name}",
                notification_type='new_application'
            )
            
            return application
            
        except Exception as e:
            db.session.rollback()
            raise