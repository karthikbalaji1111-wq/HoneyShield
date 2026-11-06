#!/usr/bin/env bash
# ==============================================================================
# HoneyShield PostgreSQL Container Entrypoint Initialization
# Placed in /docker-entrypoint-initdb.d/ to run on first database volume creation.
# ==============================================================================
set -euo pipefail

echo "[INFO] Initializing HoneyShield runtime database roles..."

APP_USER="${POSTGRES_APP_USER:-honeyshield_app}"
APP_PASSWORD="${POSTGRES_APP_PASSWORD:-honeyshield_app_password}"
DB_NAME="${POSTGRES_DB:-honeyshield_dev}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
       IF NOT EXISTS (
          SELECT FROM pg_catalog.pg_roles WHERE rolname = '${APP_USER}'
       ) THEN
          CREATE ROLE ${APP_USER} WITH LOGIN PASSWORD '${APP_PASSWORD}';
       END IF;
    END
    \$\$;

    REVOKE ALL ON SCHEMA public FROM ${APP_USER};
    REVOKE CREATE ON SCHEMA public FROM ${APP_USER};

    GRANT CONNECT ON DATABASE "${DB_NAME}" TO ${APP_USER};
    GRANT USAGE ON SCHEMA public TO ${APP_USER};

    ALTER DEFAULT PRIVILEGES FOR ROLE "${POSTGRES_USER}" IN SCHEMA public 
        GRANT USAGE, SELECT ON SEQUENCES TO ${APP_USER};
EOSQL

echo "[INFO] Runtime database role '${APP_USER}' pre-provisioned successfully."
