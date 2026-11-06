#!/usr/bin/env bash
# ==============================================================================
# HoneyShield Production PostgreSQL Restore Automation
# ==============================================================================
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <path-to-backup-file> [--force]" >&2
    exit 1
fi

BACKUP_FILE="$1"
FORCE_RESTORE="${2:-}"

POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-honeyshield}"
POSTGRES_USER="${POSTGRES_USER:-honeyshield}"
USE_DOCKER="${USE_DOCKER:-false}"
DOCKER_SERVICE="${DOCKER_SERVICE:-postgres}"
DOCKER_CONTAINER="${DOCKER_CONTAINER:-}"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "ERROR: Backup file ${BACKUP_FILE} does not exist!" >&2
    exit 1
fi

CHECKSUM_FILE="${BACKUP_FILE}.sha256"
if [ -f "${CHECKSUM_FILE}" ]; then
    echo "Verifying SHA-256 integrity checksum..."
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "${CHECKSUM_FILE}"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "${CHECKSUM_FILE}"
    else
        echo "WARNING: Neither sha256sum nor shasum available; skipping checksum check."
    fi
    echo "Checksum verified."
else
    echo "WARNING: No checksum file found at ${CHECKSUM_FILE}."
fi

if [ "${FORCE_RESTORE}" != "--force" ]; then
    echo "CAUTION: This will overwrite/restore database '${POSTGRES_DB}'."
    echo "Pass '--force' as the second argument to confirm non-interactive execution."
    read -r -p "Are you sure you want to proceed? [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY])
            ;;
        *)
            echo "Restore aborted by user."
            exit 0
            ;;
    esac
fi

echo "=== HoneyShield Restore Initiation ==="
echo "Source: ${BACKUP_FILE}"
echo "Target: ${POSTGRES_DB} on ${POSTGRES_HOST}:${POSTGRES_PORT}"

RESTORE_STATUS=0
if [ -n "${DOCKER_CONTAINER}" ]; then
    echo "Restoring via Docker container '${DOCKER_CONTAINER}'..."
    docker exec -i "${DOCKER_CONTAINER}" pg_restore \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges \
        -v < "${BACKUP_FILE}" || RESTORE_STATUS=$?
elif [ "${USE_DOCKER}" = "true" ]; then
    echo "Restoring via Docker compose service '${DOCKER_SERVICE}'..."
    docker compose exec -T "${DOCKER_SERVICE}" pg_restore \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges \
        -v < "${BACKUP_FILE}" || RESTORE_STATUS=$?
else
    echo "Restoring via local pg_restore..."
    pg_restore \
        -h "${POSTGRES_HOST}" \
        -p "${POSTGRES_PORT}" \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges \
        -v \
        "${BACKUP_FILE}" || RESTORE_STATUS=$?
fi

# pg_restore exit status:
# 0 = success
# nonzero = error during processing (corrupted archive, connection failure, syntax error)
if [ "${RESTORE_STATUS}" -ne 0 ]; then
    echo "ERROR: pg_restore failed with exit code ${RESTORE_STATUS}!" >&2
    exit "${RESTORE_STATUS}"
fi

echo "Verifying restored database schema..."
if [ -n "${DOCKER_CONTAINER}" ]; then
    TABLE_COUNT=$(docker exec -i "${DOCKER_CONTAINER}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';")
elif [ "${USE_DOCKER}" = "true" ]; then
    TABLE_COUNT=$(docker compose exec -T "${DOCKER_SERVICE}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';")
else
    TABLE_COUNT=$(psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';")
fi

echo "Restored public tables count: ${TABLE_COUNT}"
if [ "${TABLE_COUNT}" -eq 0 ]; then
    echo "ERROR: Restored database contains 0 public tables!" >&2
    exit 1
fi

echo "=== Restore Execution Completed ==="
