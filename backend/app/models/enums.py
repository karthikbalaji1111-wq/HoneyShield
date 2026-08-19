from enum import Enum as PyEnum


class HoneyTokenType(str, PyEnum):
    URL = "URL"
    FORM_FIELD = "FORM_FIELD"
    LINK = "LINK"
    PIXEL = "PIXEL"
    API_KEY = "API_KEY"


class EventSeverity(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Role(str, PyEnum):
    SYSTEM_ADMIN = "SYSTEM_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    TENANT_USER = "TENANT_USER"
