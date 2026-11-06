#!/usr/bin/env bash
# ==============================================================================
# HoneyShield Principle of Least Privilege: Runtime Application Role Provisioning
# ==============================================================================
# Creates and configures the unprivileged honeyshield_app role.
# Decouples runtime application CRUD access from migration/DDL administrative ownership.
#
# Enforces defense-in-depth for forensic immutability:
# - detection_events and audit_logs: SELECT, INSERT only (UPDATE/DELETE/TRUNCATE denied at grant level)
# - mutable tables (tenants, projects, users, honey_tokens, application_configs): SELECT, INSERT, UPDATE, DELETE
# - DDL operations (ALTER, DROP, CREATE) and trigger management (DISABLE TRIGGER): Denied (non-owner)
# ==============================================================================

set -euo pipefail

DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-honeyshield_dev}"
ADMIN_USER="${POSTGRES_USER:-honeyshield}"
ADMIN_PASSWORD="${POSTGRES_PASSWORD:-honeyshield_dev_password}"

APP_USER="${POSTGRES_APP_USER:-honeyshield_app}"
APP_PASSWORD="${POSTGRES_APP_PASSWORD:-honeyshield_app_password}"

USE_DOCKER="${USE_DOCKER:-false}"
DOCKER_SERVICE="${DOCKER_SERVICE:-postgres}"
DOCKER_CONTAINER="${DOCKER_CONTAINER:-}"

echo "[INFO] Provisioning runtime role '${APP_USER}' on database '${DB_NAME}'..."

SQL=$(cat <<EOSQL
-- 1. Create runtime role if not exists
DO \$\$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = '${APP_USER}'
   ) THEN
      CREATE ROLE ${APP_USER} WITH LOGIN PASSWORD '${APP_PASSWORD}';
   ELSE
      ALTER ROLE ${APP_USER} WITH LOGIN PASSWORD '${APP_PASSWORD}';
   END IF;
END
\$\$;

-- 2. Revoke dangerous global privileges
REVOKE ALL ON SCHEMA public FROM ${APP_USER};
REVOKE CREATE ON SCHEMA public FROM ${APP_USER};

-- 3. Grant database connection and schema usage
GRANT CONNECT ON DATABASE "${DB_NAME}" TO ${APP_USER};
GRANT USAGE ON SCHEMA public TO ${APP_USER};

-- 4. Grant standard CRUD on mutable application tables
DO \$\$
DECLARE
    tbl text;
    mutable_tables text[] := ARRAY['tenants', 'projects', 'users', 'honey_tokens', 'application_configs'];
BEGIN
    FOREACH tbl IN ARRAY mutable_tables LOOP
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I TO %I', tbl, '${APP_USER}');
        END IF;
    END LOOP;
END
\$\$;

-- 5. Enforce Forensic Immutability at SQL privilege layer:
-- Runtime role is granted SELECT and INSERT ONLY on audit and detection tables.
-- UPDATE, DELETE, and TRUNCATE are strictly denied.
DO \$\$
DECLARE
    tbl text;
    forensic_tables text[] := ARRAY['detection_events', 'audit_logs'];
BEGIN
    FOREACH tbl IN ARRAY forensic_tables LOOP
        IF EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
            EXECUTE format('REVOKE ALL ON TABLE %I FROM %I', tbl, '${APP_USER}');
            EXECUTE format('GRANT SELECT, INSERT ON TABLE %I TO %I', tbl, '${APP_USER}');
        END IF;
    END LOOP;
END
\$\$;

-- 6. Sequence usage for ID generation
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${APP_USER};

-- 7. Ensure future tables created by migrations follow least-privilege defaults
ALTER DEFAULT PRIVILEGES FOR ROLE ${ADMIN_USER} IN SCHEMA public 
    GRANT USAGE, SELECT ON SEQUENCES TO ${APP_USER};
EOSQL
)

if [ -n "${DOCKER_CONTAINER}" ]; then
    echo "[INFO] Executing psql via Docker container '${DOCKER_CONTAINER}'..."
    echo "${SQL}" | docker exec -i -e PGPASSWORD="${ADMIN_PASSWORD}" "${DOCKER_CONTAINER}" psql -U "${ADMIN_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1
elif [ "${USE_DOCKER}" = "true" ]; then
    echo "[INFO] Executing psql via Docker compose service '${DOCKER_SERVICE}'..."
    echo "${SQL}" | docker compose exec -T -e PGPASSWORD="${ADMIN_PASSWORD}" "${DOCKER_SERVICE}" psql -U "${ADMIN_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1
else
    echo "[INFO] Executing local psql..."
    echo "${SQL}" | PGPASSWORD="${ADMIN_PASSWORD}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${ADMIN_USER}" -d "${DB_NAME}" -v ON_ERROR_STOP=1
fi

echo "[INFO] Runtime role '${APP_USER}' successfully provisioned and secured."
