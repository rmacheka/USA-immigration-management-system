class ImmigrationSystemError(Exception):
    """Base exception class for the application"""
    pass

class PermissionDeniedError(ImmigrationSystemError):
    """Raised when user lacks required permissions"""
    pass

class InvalidApplicationError(ImmigrationSystemError):
    """Raised for invalid application submissions"""
    pass