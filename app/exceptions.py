# exceptions.py - Custom exceptions
class BaseAppException(Exception):
    """Base application exception"""
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class NotFoundException(BaseAppException):
    """Exception raised when a resource is not found"""
    pass


class ValidationError(BaseAppException):
    """Exception raised when validation fails"""
    pass


class AuthenticationError(BaseAppException):
    """Exception raised for authentication issues"""
    pass


class AuthorizationError(BaseAppException):
    """Exception raised for authorization issues"""
    pass
