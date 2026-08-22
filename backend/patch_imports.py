import app.core.exceptions
from app.core.auth_exceptions import ForbiddenError, UnauthorizedError
app.core.exceptions.ForbiddenError = ForbiddenError
app.core.exceptions.UnauthorizedError = UnauthorizedError
