"""Add database-level immutability triggers for forensic audit and detection tables.

Revision ID: 20261019_01
Revises: 20261002_01
Create Date: 2026-10-19 12:00:00.000000+00:00

Phase 4 forensic integrity:
- Enforces strict immutability on detection_events and audit_logs tables at the database level.
- Adds BEFORE UPDATE OR DELETE triggers that raise exceptions upon any attempted DML modification or deletion.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '20261019_01'
down_revision: Union[str, None] = '20261002_01'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("""
            CREATE OR REPLACE FUNCTION prevent_forensic_modification()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'Forensic records are immutable and cannot be updated or deleted';
            END;
            $$ LANGUAGE plpgsql;
        """))

        op.execute(sa.text("""
            CREATE TRIGGER trg_detection_events_immutable
            BEFORE UPDATE OR DELETE ON detection_events
            FOR EACH ROW EXECUTE FUNCTION prevent_forensic_modification();
        """))

        op.execute(sa.text("""
            CREATE TRIGGER trg_detection_events_no_truncate
            BEFORE TRUNCATE ON detection_events
            FOR EACH STATEMENT EXECUTE FUNCTION prevent_forensic_modification();
        """))

        op.execute(sa.text("""
            CREATE TRIGGER trg_audit_logs_immutable
            BEFORE UPDATE OR DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION prevent_forensic_modification();
        """))

        op.execute(sa.text("""
            CREATE TRIGGER trg_audit_logs_no_truncate
            BEFORE TRUNCATE ON audit_logs
            FOR EACH STATEMENT EXECUTE FUNCTION prevent_forensic_modification();
        """))
    elif bind.dialect.name == "sqlite":
        op.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_detection_events_no_update
            BEFORE UPDATE ON detection_events
            BEGIN
                SELECT RAISE(ABORT, 'Forensic records are immutable and cannot be updated');
            END;
        """))
        op.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_detection_events_no_delete
            BEFORE DELETE ON detection_events
            BEGIN
                SELECT RAISE(ABORT, 'Forensic records are immutable and cannot be deleted');
            END;
        """))
        op.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Forensic records are immutable and cannot be updated');
            END;
        """))
        op.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Forensic records are immutable and cannot be deleted');
            END;
        """))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_logs_no_truncate ON audit_logs;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_detection_events_no_truncate ON detection_events;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_detection_events_immutable ON detection_events;"))
        op.execute(sa.text("DROP FUNCTION IF EXISTS prevent_forensic_modification();"))
    elif bind.dialect.name == "sqlite":
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_logs_no_delete;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_logs_no_update;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_detection_events_no_delete;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_detection_events_no_update;"))
