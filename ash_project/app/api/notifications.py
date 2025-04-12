from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.services import NotificationService

class NotificationAPI(Resource):
    @jwt_required()
    def get(self):
        """Get user notifications"""
        user_id = get_jwt_identity()
        notifications = NotificationService.get_user_notifications(user_id)
        return [n.to_dict() for n in notifications]

class NotificationReadAPI(Resource):
    @jwt_required()
    def put(self, notification_id):
        """Mark notification as read"""
        user_id = get_jwt_identity()
        NotificationService.mark_as_read(notification_id, user_id)
        return {'message': 'Notification marked as read'}