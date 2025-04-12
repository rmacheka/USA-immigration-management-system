from app.models import Notification
from app.extensions import db

class NotificationService:
    @staticmethod
    def get_user_notifications(user_id, limit=5):
        """Get user notifications with pagination"""
        return Notification.query.filter_by(user_id=user_id)\
            .order_by(Notification.created_at.desc())\
            .limit(limit)\
            .all()
    
    @staticmethod
    def create_notification(user_id, message, notification_type='info'):
        """Create a new notification"""
        notification = Notification(
            user_id=user_id,
            message=message,
            notification_type=notification_type,
            is_read=False
        )
        db.session.add(notification)
        db.session.commit()
        return notification
    
    @staticmethod
    def mark_as_read(notification_id, user_id):
        """Mark notification as read"""
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=user_id
        ).first()
        
        if notification:
            notification.is_read = True
            db.session.commit()