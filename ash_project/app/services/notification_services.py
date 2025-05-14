from datetime import datetime
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError

from ash_project.app.extensions import db
from ash_project.app.models.notification import Notification

class NotificationService:
    @staticmethod
    def create_notification(
        user_id: int,
        message: str,
        notification_type: str,
        is_read: bool = False,
        related_entity_id: Optional[int] = None
    ) -> Notification:
        """
        Create a new notification
        Returns: Notification object
        """
        try:
            notification = Notification(
                user_id=user_id,
                message=message,
                notification_type=notification_type,
                is_read=is_read,
                created_at=datetime.utcnow(),
                related_entity_id=related_entity_id
            )
            
            db.session.add(notification)
            db.session.commit()
            
            # For production: Add actual email/SMS integration here
            # send_notification_email(notification)
            
            return notification
            
        except SQLAlchemyError as e:
            db.session.rollback()
            raise ValueError(f"Database error creating notification: {str(e)}")
        except Exception as e:
            raise ValueError(f"Error creating notification: {str(e)}")

    @staticmethod
    def get_user_notifications(user_id: int) -> list[Notification]:
        """Get all notifications for a user"""
        try:
            return Notification.query.filter_by(user_id=user_id)\
                .order_by(Notification.created_at.desc())\
                .all()
        except SQLAlchemyError as e:
            raise ValueError(f"Database error fetching notifications: {str(e)}")

    @staticmethod
    def mark_as_read(notification_id: int) -> Notification:
        """Mark a notification as read"""
        try:
            notification = Notification.query.get(notification_id)
            if notification:
                notification.is_read = True
                db.session.commit()
            return notification
        except SQLAlchemyError as e:
            db.session.rollback()
            raise ValueError(f"Database error updating notification: {str(e)}")