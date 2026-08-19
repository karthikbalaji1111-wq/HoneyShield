"""User persistence queries."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository for User lookup operations."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, User)

    def get_by_email(self, email: str) -> User | None:
        """Return the User with the given email address, or None."""
        stmt = select(User).where(User.email == email)
        return self.session.scalar(stmt)

    def get_by_id(self, id: int) -> User | None:
        """Return the User with the given primary key, or None."""
        return self.session.get(User, id)
