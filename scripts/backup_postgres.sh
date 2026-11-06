#!/usr/bin/env bash
# ==============================================================================
# HoneyShield Production PostgreSQL Backup Automation
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-honeyshield}"
POSTGRES_USER="${POSTGRES_USER:-honeyshield}"
USE_DOCKER="${USE_DOCKER:-false}"
DOCKER_SERVICE="${DOCKER_SERVICE:-postgres}"
DOCKER_CONTAINER="${DOCKER_CONTAINER:-}"

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

BACKUP_FILE="${BACKUP_DIR}/${POSTGRES_DB}_${TIMESTAMP}.dump"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

echo "=== HoneyShield Backup Initiation: ${TIMESTAMP} ==="
echo "Target DB: ${POSTGRES_DB} on ${POSTGRES_HOST}:${POSTGRES_PORT}"
echo "Output: ${BACKUP_FILE}"

if [ -n "${DOCKER_CONTAINER}" ]; then
    echo "Executing pg_dump via Docker container '${DOCKER_CONTAINER}'..."
    docker exec -i "${DOCKER_CONTAINER}" pg_dump \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        -F c \
        -b \
        -v > "${BACKUP_FILE}"
elif [ "${USE_DOCKER}" = "true" ]; then
    echo "Executing pg_dump via Docker compose service '${DOCKER_SERVICE}'..."
    docker compose exec -T "${DOCKER_SERVICE}" pg_dump \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        -F c \
        -b \
        -v > "${BACKUP_FILE}"
else
    echo "Executing local pg_dump..."
    pg_dump \
        -h "${POSTGRES_HOST}" \
        -p "${POSTGRES_PORT}" \
        -U "${POSTGRES_USER}" \
        -d "${POSTGRES_DB}" \
        -F c \
        -b \
        -v \
        -f "${BACKUP_FILE}"
fi

# Verify backup existence and non-zero size
if [ ! -s "${BACKUP_FILE}" ]; then
    echo "ERROR: Backup file ${BACKUP_FILE} is missing or empty!" >&2
    rm -f "${BACKUP_FILE}"
    exit 1
fi

# Secure file permissions (Owner read/write only)
chmod 600 "${BACKUP_FILE}"

# Generate SHA-256 integrity checksum
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${BACKUP_FILE}" > "${CHECKSUM_FILE}"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${BACKUP_FILE}" > "${CHECKSUM_FILE}"
else
    openssl dgst -sha256 "${BACKUP_FILE}" > "${CHECKSUM_FILE}"
fi
chmod 600 "${CHECKSUM_FILE}"

BACKUP_SIZE=$(stat -f%z "${BACKUP_FILE}" 2>/dev/null || stat -c%s "${BACKUP_FILE}" 2>/dev/null || wc -c < "${BACKUP_FILE}")

echo "=== Backup Completed Successfully ==="
echo "File:     ${BACKUP_FILE} (${BACKUP_SIZE} bytes)"
echo "Checksum: $(cat "${CHECKSUM_FILE}")"
