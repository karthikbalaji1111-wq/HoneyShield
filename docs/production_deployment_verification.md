# HoneyShield — Production Deployment & Release Verification Guide
**Document Version:** 1.0  
**Target Environment:** Staging & Production Deployment  
**Classification:** Release Engineering & Verification Protocol

---

## 1. Production Deployment Prerequisites

Before deploying HoneyShield to any staging or production cluster, verify that the following requirements are met:

### A. Environment Configuration & Secrets
1. **Application Environment:** Set `APP_ENV=production` (or `staging`).
2. **Database Credentials:**
   - `POSTGRES_DB`: Name of the production database.
   - `POSTGRES_USER`: Dedicated migration/admin user (`honeyshield_migration`).
   - `POSTGRES_PASSWORD`: Cryptographically secure password (minimum 32 characters, no default/dev placeholders).
   - `POSTGRES_APP_USER`: Dedicated unprivileged application user (`honeyshield_app`).
   - `POSTGRES_APP_PASSWORD`: Distinct cryptographically secure password.
3. **JWT Signing Key:**
   - `JWT_SECRET_KEY`: Minimum 32 bytes generated via `openssl rand -hex 32`. Rejects default dev keys.
4. **Proxy Trust:**
   - `TRUSTED_PROXIES`: Explicit list or CIDR blocks of upstream proxies (e.g. `10.0.0.0/8`, `172.16.0.0/12`).

### B. Production TLS Certificates
1. Place CA-signed certificate and private key in `proxy/certs/server.crt` and `proxy/certs/server.key`.
2. Format: RSA or ECDSA private key without passphrase, standard PEM encoding.
3. Permissions: Ensure `0600` on `server.key` and `0644` on `server.crt`.

---

## 2. Deployment Procedure

```bash
# 1. Validate Docker Compose configuration
docker compose config --quiet

# 2. Build backend container with unprivileged user (UID 10001)
docker compose build backend

# 3. Start database service and wait for healthcheck
docker compose up -d postgres
docker compose exec postgres pg_isready -U honeyshield_migration -d honeyshield

# 4. Execute database migrations as migration owner
MIGRATION_DATABASE_URL="postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}" \
docker compose run --rm backend alembic -c backend/alembic.ini upgrade head

# 5. Provision unprivileged runtime role permissions
USE_DOCKER=true DOCKER_SERVICE=postgres ./scripts/provision_app_role.sh

# 6. Bootstrap system administrator (first time only)
docker compose run --rm backend python -m app.bootstrap --email admin@prod.internal

# 7. Start backend application and Nginx reverse proxy
docker compose up -d backend nginx
```

---

## 3. Staging Deployment Smoke Test Protocol

Execute the following end-to-end smoke tests against the deployed stack:

### Check 1: Nginx TLS & HTTPS Redirection
```bash
# Verify HTTP redirects to HTTPS
curl -I http://127.0.0.1:8080/health
# Expected: HTTP/1.1 301 Moved Permanently -> https://...

# Verify HTTPS Liveness (without DB)
curl -k https://127.0.0.1:8443/health
# Expected: {"status":"healthy"}
```

### Check 2: API Readiness Gate (DB & Alembic Head Verification)
```bash
curl -k https://127.0.0.1:8443/api/v1/ready
# Expected: {"status":"ready","database":"connected","alembic_head":"20261019_01"}
```

### Check 3: Real-Time Event Streaming (WebSocket & SSE over TLS)
Verify full-duplex WebSocket upgrade and event reception through Nginx:
- Connect to `wss://127.0.0.1:8443/api/v1/events/stream/ws`.
- Authenticate via `{"type":"auth","token":"<JWT>"}`.
- Verify `{"type":"auth_success"}`.
- Trigger honey token via `GET https://127.0.0.1:8443/t/<TOKEN_VALUE>`.
- Verify real-time event delivery over WebSocket.
- Verify database connection pool checkouts return to 0 during active stream.

### Check 4: Rate Limiting Admission Control
- Send 125 rapid requests to an unauthenticated endpoint.
- Verify HTTP 429 received after request 120 with valid `Retry-After` header.

---

## 4. CI/CD Workflow Status & External Release Gate

- **Local Automated Test Suite:**
  - Full pytest regression: **283 passed of 283 tests** (100% pass rate).
  - Streaming warning test: Zero `RuntimeWarning` unawaited coroutine warnings.
  - Zero unhandled exceptions.
- **Workflow Configuration (`.github/workflows/ci.yml`):**
  - Fully validated YAML syntax and migration discovery steps.
  - Includes test execution, linting, migration check, and security scanning.
- **External Release Gate:**
  - Local verification: **PASS**.
  - External GitHub Actions execution: **BLOCKED** pending repository remote push authorization (git push and external CI triggering require administrative repository access).
