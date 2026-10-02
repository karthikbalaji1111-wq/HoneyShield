from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, Enum, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import Role


class User(BaseModel):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("(role = 'SYSTEM_ADMIN' AND tenant_id IS NULL) OR "
                        "(role IN ('TENANT_ADMIN', 'TENANT_USER') AND tenant_id IS NOT NULL)",
                        name="role_tenant_scope"),
        CheckConstraint("token_version >= 0", name="token_version_nonnegative"),
        Index("ix_users_tenant_created_at_id", "tenant_id", text("created_at DESC"), text("id DESC")),
    )

    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, validate_strings=True,
                                          create_constraint=True, name="valid_user_role", length=50), nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    tenant_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)

    tenant: Mapped["Tenant"] = relationship("Tenant")
