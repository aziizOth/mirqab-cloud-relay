"""
Mirqab Cloud Relay SDK - Exception Classes
Custom exceptions for Cloud Relay client operations
"""


class RelayError(Exception):
    """Base exception for all Cloud Relay errors"""

    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.error_code = error_code


class AuthenticationError(RelayError):
    """Raised when authentication with Cloud Relay fails"""
    pass


class ConnectionError(RelayError):
    """Raised when connection to Cloud Relay fails"""
    pass


class ProvisioningError(RelayError):
    """Raised when tenant provisioning fails"""
    pass


class ChannelError(RelayError):
    """Raised when C2 channel operations fail"""
    pass


class PayloadError(RelayError):
    """Raised when payload operations fail"""
    pass


class QuotaExceededError(RelayError):
    """Raised when tenant quota is exceeded"""
    pass


class TenantSuspendedError(RelayError):
    """Raised when tenant is suspended"""
    pass


class TenantExpiredError(RelayError):
    """Raised when tenant subscription has expired"""
    pass
