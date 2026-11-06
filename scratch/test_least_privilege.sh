#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="disposable-least-privilege-5434"
PORT=5434
DB="honeyshield_test"
MIGRATION_USER="honeyshield_migration"
MIGRATION_PASS="migration_secret_pass"
APP_USER="honeyshield_app"
APP_PASS="app_secret_pass"

echo "[TEST] Starting disposable PostgreSQL container '${CONTAINER_NAME}'..."
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${PORT}:5432" \
    -e POSTGRES_DB="${DB}" \
    -e POSTGRES_USER="${MIGRATION_USER}" \
    -e POSTGRES_PASSWORD="${MIGRATION_PASS}" \
    -e POSTGRES_APP_USER="${APP_USER}" \
    -e POSTGRES_APP_PASSWORD="${APP_PASS}" \
    -v "$(pwd)/docker/init-db.sh:/docker-entrypoint-initdb.d/init-db.sh:ro" \
    postgres:16

echo "[TEST] Waiting for PostgreSQL readiness..."
for i in {1..30}; do
    if docker exec "${CONTAINER_NAME}" pg_isready -U "${MIGRATION_USER}" -d "${DB}" > /dev/null 2>&1; then
        echo "[TEST] Database ready after $i seconds."
        break
    fi
    sleep 1
done

echo "[TEST] Running Alembic migrations to head as '${MIGRATION_USER}'..."
(cd backend && MIGRATION_DATABASE_URL="postgresql+psycopg2://${MIGRATION_USER}:${MIGRATION_PASS}@localhost:${PORT}/${DB}" \
PYTHONPATH=. uv run --with-requirements requirements.txt alembic -c alembic.ini upgrade head)

echo "[TEST] Executing least-privilege role provisioning..."
POSTGRES_HOST=localhost \
POSTGRES_PORT="${PORT}" \
POSTGRES_DB="${DB}" \
POSTGRES_USER="${MIGRATION_USER}" \
POSTGRES_PASSWORD="${MIGRATION_PASS}" \
POSTGRES_APP_USER="${APP_USER}" \
POSTGRES_APP_PASSWORD="${APP_PASS}" \
DOCKER_CONTAINER="${CONTAINER_NAME}" \
./scripts/provision_app_role.sh

echo "[TEST] Verifying permissions for runtime role '${APP_USER}'..."

# Test 1: Insert into mutable table (tenants) -> SHOULD SUCCEED
echo -n "Test 1: App role INSERT into 'tenants'... "
docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "INSERT INTO tenants (name, slug, is_active) VALUES ('Test Corp', 'test-corp', true);" > /dev/null
echo "PASS"

# Test 2: Select from 'tenants' -> SHOULD SUCCEED
echo -n "Test 2: App role SELECT from 'tenants'... "
TENANT_ID=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -t -A -c \
    "SELECT id FROM tenants WHERE slug = 'test-corp';")
if [ -n "$TENANT_ID" ]; then
    echo "PASS (id=${TENANT_ID})"
else
    echo "FAIL"
    exit 1
fi

# Test 2b: App role INSERT into 'projects' and 'honey_tokens' -> SHOULD SUCCEED
echo -n "Test 2b: App role INSERT into 'projects' and 'honey_tokens'... "
docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "INSERT INTO projects (tenant_id, name, domain, is_active) VALUES (${TENANT_ID}, 'Test Project', 'test.corp', true);" > /dev/null
PROJECT_ID=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -t -A -c \
    "SELECT id FROM projects WHERE domain = 'test.corp';" | head -n 1)

docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "INSERT INTO honey_tokens (project_id, token_type, token_value, is_active) VALUES (${PROJECT_ID}, 'API_KEY', 'HONEY_TEST_VAL', true);" > /dev/null
TOKEN_ID=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -t -A -c \
    "SELECT id FROM honey_tokens WHERE token_value = 'HONEY_TEST_VAL';" | head -n 1)
echo "PASS (proj=${PROJECT_ID}, tok=${TOKEN_ID})"

# Test 3: Insert into forensic table 'detection_events' -> SHOULD SUCCEED
echo -n "Test 3: App role INSERT into 'detection_events'... "
docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "INSERT INTO detection_events (honey_token_id, ip_address, request_path, http_method, severity)
     VALUES (${TOKEN_ID}, '127.0.0.1', '/api/test', 'GET', 'HIGH');" > /dev/null
echo "PASS"

# Test 3b: Insert into forensic table 'audit_logs' -> SHOULD SUCCEED
echo -n "Test 3b: App role INSERT into 'audit_logs'... "
docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "INSERT INTO audit_logs (tenant_id, event_type, severity, message) VALUES (${TENANT_ID}, 'SECURITY_TEST', 'INFO', 'Test log message');" > /dev/null
echo "PASS"

# Test 4: Select from forensic table 'detection_events' -> SHOULD SUCCEED
echo -n "Test 4: App role SELECT from 'detection_events'... "
EVENT_COUNT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -t -A -c \
    "SELECT count(*) FROM detection_events;" | head -n 1)
if [ "$EVENT_COUNT" -eq 1 ]; then
    echo "PASS (count=${EVENT_COUNT})"
else
    echo "FAIL (count=${EVENT_COUNT})"
    exit 1
fi

# Test 4b: Select from forensic table 'audit_logs' -> SHOULD SUCCEED
echo -n "Test 4b: App role SELECT from 'audit_logs'... "
LOG_COUNT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -t -A -c \
    "SELECT count(*) FROM audit_logs;" | head -n 1)
if [ "$LOG_COUNT" -eq 1 ]; then
    echo "PASS (count=${LOG_COUNT})"
else
    echo "FAIL (count=${LOG_COUNT})"
    exit 1
fi

# Test 5: UPDATE on 'detection_events' -> MUST FAIL (Permission Denied)
echo -n "Test 5: App role UPDATE on 'detection_events' denied... "
ERR_OUT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "UPDATE detection_events SET ip_address = '9.9.9.9';" 2>&1 || true)
if echo "$ERR_OUT" | grep -q "permission denied for table detection_events"; then
    echo "PASS (Permission Denied)"
else
    echo "FAIL (Unexpected output: $ERR_OUT)"
    exit 1
fi

# Test 5b: UPDATE on 'audit_logs' -> MUST FAIL (Permission Denied)
echo -n "Test 5b: App role UPDATE on 'audit_logs' denied... "
ERR_OUT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "UPDATE audit_logs SET message = 'TAMPERED';" 2>&1 || true)
if echo "$ERR_OUT" | grep -q "permission denied for table audit_logs"; then
    echo "PASS (Permission Denied)"
else
    echo "FAIL (Unexpected output: $ERR_OUT)"
    exit 1
fi

# Test 6: DELETE on 'detection_events' -> MUST FAIL (Permission Denied)
echo -n "Test 6: App role DELETE on 'detection_events' denied... "
ERR_OUT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "DELETE FROM detection_events;" 2>&1 || true)
if echo "$ERR_OUT" | grep -q "permission denied for table detection_events"; then
    echo "PASS (Permission Denied)"
else
    echo "FAIL (Unexpected output: $ERR_OUT)"
    exit 1
fi

# Test 6b: DELETE on 'audit_logs' -> MUST FAIL (Permission Denied)
echo -n "Test 6b: App role DELETE on 'audit_logs' denied... "
ERR_OUT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "DELETE FROM audit_logs;" 2>&1 || true)
if echo "$ERR_OUT" | grep -q "permission denied for table audit_logs"; then
    echo "PASS (Permission Denied)"
else
    echo "FAIL (Unexpected output: $ERR_OUT)"
    exit 1
fi

# Test 7: TRUNCATE on 'detection_events' -> MUST FAIL (Permission Denied)
echo -n "Test 7: App role TRUNCATE on 'detection_events' denied... "
ERR_OUT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "TRUNCATE detection_events;" 2>&1 || true)
if echo "$ERR_OUT" | grep -q "permission denied for table detection_events"; then
    echo "PASS (Permission Denied)"
else
    echo "FAIL (Unexpected output: $ERR_OUT)"
    exit 1
fi

# Test 8: DISABLE TRIGGER on 'detection_events' -> MUST FAIL (Must be owner)
echo -n "Test 8: App role ALTER TABLE DISABLE TRIGGER denied... "
ERR_OUT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "ALTER TABLE detection_events DISABLE TRIGGER ALL;" 2>&1 || true)
if echo "$ERR_OUT" | grep -qi "must be owner of table detection_events"; then
    echo "PASS (Must be owner of table)"
else
    echo "FAIL (Unexpected output: $ERR_OUT)"
    exit 1
fi

# Test 9: DROP TABLE on 'detection_events' -> MUST FAIL (Must be owner)
echo -n "Test 9: App role DROP TABLE denied... "
ERR_OUT=$(docker exec "${CONTAINER_NAME}" psql -U "${APP_USER}" -d "${DB}" -c \
    "DROP TABLE detection_events;" 2>&1 || true)
if echo "$ERR_OUT" | grep -qi "must be owner of table detection_events"; then
    echo "PASS (Must be owner of table)"
else
    echo "FAIL (Unexpected output: $ERR_OUT)"
    exit 1
fi

echo "[TEST] ALL 9 LEAST-PRIVILEGE ROLE TESTS PASSED PERFECTLY!"

# Clean up
docker rm -f "${CONTAINER_NAME}" > /dev/null
echo "[TEST] Disposable container removed."
