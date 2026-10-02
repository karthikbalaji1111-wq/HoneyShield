from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import HoneyTokenType
from app.models.honey_token import HoneyToken
from app.repositories.base import BaseRepository


class HoneyTokenRepository(BaseRepository[HoneyToken]):
    def __init__(self, session: Session) -> None:
        super().__init__(session, HoneyToken)

    def get_by_token(self, token_value: str) -> HoneyToken | None:
        stmt = select(HoneyToken).where(HoneyToken.token_value == token_value)
        return self.session.scalar(stmt)

    def list_by_project(self, project_id: int, limit: int | None = None, offset: int = 0) -> list[HoneyToken]:
        stmt = select(HoneyToken).where(HoneyToken.project_id == project_id).order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc()).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.session.scalars(stmt).all())

    def list_active(self, project_id: int | None = None, limit: int | None = None, offset: int = 0) -> list[HoneyToken]:
        stmt = select(HoneyToken).where(HoneyToken.is_active.is_(True))
        if project_id is not None:
            stmt = stmt.where(HoneyToken.project_id == project_id)
        stmt = stmt.order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc()).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.session.scalars(stmt).all())

    def list_by_type(self, token_type: HoneyTokenType, project_id: int | None = None, limit: int | None = None, offset: int = 0) -> list[HoneyToken]:
        stmt = select(HoneyToken).where(HoneyToken.token_type == token_type)
        if project_id is not None:
            stmt = stmt.where(HoneyToken.project_id == project_id)
        stmt = stmt.order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc()).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.session.scalars(stmt).all())

    def list_for_tenant(
        self,
        tenant_id: int,
        active_only: bool = True,
        project_id: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[HoneyToken]:
        from app.models.project import Project
        stmt = (
            select(HoneyToken)
            .join(Project, HoneyToken.project_id == Project.id)
            .where(Project.tenant_id == tenant_id)
        )
        if active_only:
            stmt = stmt.where(HoneyToken.is_active.is_(True))
        if project_id is not None:
            stmt = stmt.where(HoneyToken.project_id == project_id)
        stmt = stmt.order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc()).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.session.scalars(stmt).all())

    def list_global(
        self,
        active_only: bool = True,
        project_id: int | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[HoneyToken]:
        stmt = select(HoneyToken)
        if active_only:
            stmt = stmt.where(HoneyToken.is_active.is_(True))
        if project_id is not None:
            stmt = stmt.where(HoneyToken.project_id == project_id)
        stmt = stmt.order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc()).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.session.scalars(stmt).all())
