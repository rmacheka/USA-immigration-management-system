from flask import jsonify
from werkzeug.http import HTTP_STATUS_CODES

def register_error_handlers(app):
    @app.errorhandler(400)
    def bad_request_error(error):
        return jsonify({
            'error': HTTP_STATUS_CODES.get(400),
            'message': str(error.description) if hasattr(error, 'description') else 'Bad request'
        }), 400
    
    @app.errorhandler(PermissionDeniedError)
    def handle_permission_denied(error):
        return jsonify({
            'error': 'Permission denied',
            'message': str(error)
        }), 403