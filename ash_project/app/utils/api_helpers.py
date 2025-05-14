from flask import jsonify
from functools import wraps

def standard_response(func):
    """Decorator to standardize API responses"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            if isinstance(result, tuple) and len(result) == 2:
                data, status_code = result
                return jsonify({
                    'success': status_code < 400,
                    'data': data,
                    'error': None
                }), status_code
            return jsonify({
                'success': True,
                'data': result,
                'error': None
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'data': None,
                'error': str(e)
            }), 500
    return wrapper