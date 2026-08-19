from __future__ import annotations
from typing import Optional

"""fix audit_logs fk on delete set null

Revision ID: a3f1c9d28b74
Revises: e13aaeedde6d
Create Date: 2026-08-18 05:22:00.000000+00:00

Corrective migration for Milestone 13.

Drops the existing audit_logs foreign-key constraints on tenant_id and
project_id (which had no ON DELETE behaviour) and recreates them with
ON DELETE SET NULL.

This preserves:
  - all existing audit_logs rows
  - all existing columns
  - the audit_logs table structure
  - all unrelated tables and constraints

Historical audit records referencing a deleted tenant or project will
have their tenant_id / project_id set to NULL by PostgreSQL automatically
at the point the referenced row is deleted.
"""

from collections.abc import Sequence

from alembic import op


revision: str = 'a3f1c9d28b74'
down_revision: Optional[str] = 'e13aaeedde6d'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop existing FK constraints (no ON DELETE behaviour)
    op.drop_constraint(
        'fk_audit_logs_tenant_id_tenants',
        'audit_logs',
        type_='foreignkey',
    )
    op.drop_constraint(
        'fk_audit_logs_project_id_projects',
        'audit_logs',
        type_='foreignkey',
    )

    # Recreate with ON DELETE SET NULL
    op.create_foreign_key(
        'fk_audit_logs_tenant_id_tenants',
        'audit_logs',
        'tenants',
        ['tenant_id'],
        ['id'],
        ondelete='SET NULL',
    )
    op.create_foreign_key(
        'fk_audit_logs_project_id_projects',
        'audit_logs',
        'projects',
        ['project_id'],
        ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    # Restore original FK constraints (no ON DELETE behaviour)
    op.drop_constraint(
        'fk_audit_logs_project_id_projects',
        'audit_logs',
        type_='foreignkey',
    )
    op.drop_constraint(
        'fk_audit_logs_tenant_id_tenants',
        'audit_logs',
        type_='foreignkey',
    )

    op.create_foreign_key(
        'fk_audit_logs_project_id_projects',
        'audit_logs',
        'projects',
        ['project_id'],
        ['id'],
    )
    op.create_foreign_key(
        'fk_audit_logs_tenant_id_tenants',
        'audit_logs',
        'tenants',
        ['tenant_id'],
        ['id'],
    )
