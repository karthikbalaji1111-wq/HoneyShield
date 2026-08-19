"""HTTP exception mapping for domain and request-validation errors."""

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.core.auth_exceptions import (
    AuthenticationError,
    ForbiddenError,
    InactiveUserError,
    InvalidTokenError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.core.exceptions import (
    BusinessRuleViolationError,
    DetectionEventNotFoundError,
    DuplicateDomainError,
    DuplicateHoneyTokenError,
    DuplicateTenantError,
    HoneyShieldException,
    HoneyTokenNotFoundError,
    ProjectNotFoundError,
    TenantNotFoundError,
    ValidationError,
)


def _error_response(
    request: Request,
    status_code: int,
    detail: str,
) -> JSONResponse:
    """Build a safe error response with the current request identifier."""
    content: dict[str, Any] = {
        "detail": detail,
        "request_id": getattr(request.state, "request_id", "-"),
    }
    return JSONResponse(status_code=status_code, content=content)


async def request_validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a safe response for invalid HTTP request data."""
    del exc
    return _error_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Request validation failed",
    )


async def honeyshield_exception_handler(
    request: Request,
    exc: HoneyShieldException,
) -> JSONResponse:
    """Map HoneyShield domain exceptions to stable HTTP responses."""
    # Auth exceptions — checked before generic domain exceptions
    if isinstance(exc, (InvalidTokenError, UnauthorizedError, AuthenticationError, InactiveUserError)):
        status_code = status.HTTP_401_UNAUTHORIZED
    elif isinstance(exc, ForbiddenError):
        status_code = status.HTTP_403_FORBIDDEN
    elif isinstance(exc, UserNotFoundError):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, ValidationError):
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    elif isinstance(
        exc,
        (
            TenantNotFoundError,
            ProjectNotFoundError,
            HoneyTokenNotFoundError,
            DetectionEventNotFoundError,
        ),
    ):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(
        exc,
        (
            DuplicateTenantError,
            DuplicateDomainError,
            DuplicateHoneyTokenError,
            BusinessRuleViolationError,
        ),
    ):
        status_code = status.HTTP_409_CONFLICT
    else:
        status_code = status.HTTP_400_BAD_REQUEST

    return _error_response(
        request=request,
        status_code=status_code,
        detail=str(exc),
    )


async def integrity_error_exception_handler(
    request: Request,
    exc: IntegrityError,
) -> JSONResponse:
    """Hide database constraint details behind a conflict response."""
    del exc
    return _error_response(
        request=request,
        status_code=status.HTTP_409_CONFLICT,
        detail="The request conflicts with the current resource state",
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register application exception handlers without replacing the 500 fallback."""
    app.add_exception_handler(
        RequestValidationError,
        request_validation_exception_handler,
    )
    app.add_exception_handler(HoneyShieldException, honeyshield_exception_handler)
    app.add_exception_handler(IntegrityError, integrity_error_exception_handler)
