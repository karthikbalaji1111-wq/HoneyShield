"""Domain exceptions raised by HoneyShield services."""


class HoneyShieldException(Exception):
    """Base exception for all HoneyShield domain errors."""


class ValidationError(HoneyShieldException):
    """Raised when a service input fails domain validation."""


class BusinessRuleViolationError(HoneyShieldException):
    """Raised when an operation violates a domain rule."""


class TenantNotFoundError(HoneyShieldException):
    """Raised when a requested tenant does not exist."""


class ProjectNotFoundError(HoneyShieldException):
    """Raised when a requested project does not exist."""


class HoneyTokenNotFoundError(HoneyShieldException):
    """Raised when a requested honey token does not exist."""


class DetectionEventNotFoundError(HoneyShieldException):
    """Raised when a requested detection event does not exist."""


class DuplicateTenantError(HoneyShieldException):
    """Raised when a tenant slug is already in use."""


class DuplicateDomainError(HoneyShieldException):
    """Raised when a project domain is already in use."""


class DuplicateHoneyTokenError(HoneyShieldException):
    """Raised when a honey token value is already in use."""

class DuplicateEmailError(HoneyShieldException):
    """Raised when an email is already in use."""
