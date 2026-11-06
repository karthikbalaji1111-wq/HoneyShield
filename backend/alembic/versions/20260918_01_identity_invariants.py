"""Enforce identity scope and add session invalidation counter.

Invalid legacy data aborts migration. No identity is silently reassigned/deleted.
"""
from alembic import op
import sqlalchemy as sa

revision = "20260918_01"
down_revision = "0214dbf0f07f"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM users WHERE
        role NOT IN ('SYSTEM_ADMIN', 'TENANT_ADMIN', 'TENANT_USER')
        OR (role = 'SYSTEM_ADMIN' AND tenant_id IS NOT NULL)
        OR (role <> 'SYSTEM_ADMIN' AND tenant_id IS NULL)) THEN
        RAISE EXCEPTION 'Invalid user role/tenant rows: review and repair explicitly before migration';
      END IF;
    END $$""")
    op.add_column("users", sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
    op.create_check_constraint("valid_user_role", "users", "role IN ('SYSTEM_ADMIN', 'TENANT_ADMIN', 'TENANT_USER')")
    op.create_check_constraint("role_tenant_scope", "users",
                               "(role = 'SYSTEM_ADMIN' AND tenant_id IS NULL) OR "
                               "(role IN ('TENANT_ADMIN', 'TENANT_USER') AND tenant_id IS NOT NULL)")
    op.create_check_constraint("token_version_nonnegative", "users", "token_version >= 0")


def downgrade():
    op.drop_constraint(op.f("ck_users_token_version_nonnegative"), "users", type_="check")
    op.drop_constraint(op.f("ck_users_role_tenant_scope"), "users", type_="check")
    op.drop_constraint(op.f("ck_users_valid_user_role"), "users", type_="check")
    op.drop_column("users", "token_version")
