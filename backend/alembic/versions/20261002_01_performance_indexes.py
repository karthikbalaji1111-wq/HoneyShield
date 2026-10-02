"""Add composite b-tree indexes on users and audit_logs.

Revision ID: 20261002_01
Revises: 20260918_01
Create Date: 2026-10-02 05:30:00.000000+00:00

Phase 6 performance optimization:
- Indexes users (tenant_id, created_at DESC, id DESC) to eliminate sort overhead and support keyset/offset pagination on tenant user listings.
- Indexes audit_logs (tenant_id, created_at DESC, id DESC) to eliminate sort overhead on append-only forensic audit log tables.
- Leading column tenant_id satisfies foreign-key constraint and cascade checks.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '20261002_01'
down_revision: Union[str, None] = '20260918_01'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        op.f('ix_users_tenant_created_at_id'),
        'users',
        ['tenant_id', sa.text('created_at DESC'), sa.text('id DESC')],
        unique=False,
    )
    op.create_index(
        op.f('ix_audit_logs_tenant_created_at_id'),
        'audit_logs',
        ['tenant_id', sa.text('created_at DESC'), sa.text('id DESC')],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_audit_logs_tenant_created_at_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_users_tenant_created_at_id'), table_name='users')
