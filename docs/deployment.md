# Deployment foundation (not a production certification)

This backend currently requires one worker and one replica. PostgreSQL event
persistence and best-effort, process-local live notification are different
guarantees. Redis is not the event transport. There is no replay or outbox.

## Secrets

Copy `.env.example` locally and provision a unique database password and JWT
signing key. Generate the signing key with `openssl rand -hex 32`; supply it
through protected deployment environment/secrets tooling. Never commit `.env`.
Signing keys are required and must contain at least 32 bytes without surrounding
whitespace. Length validation is not proof of random entropy. No default admin
or fallback signing key is created. Keep the signing key stable across restarts;
changing it invalidates existing access tokens.

Use separate POSTGRES_* settings for credentials with reserved characters.
If DATABASE_URL is supplied explicitly, it must already be a correctly escaped
SQLAlchemy URL using the installed `postgresql+psycopg2` driver.

## Controlled first deployment

From the repository root, with Docker available and secrets supplied:

```sh
docker compose config --quiet
docker compose build backend
docker compose up -d postgres
docker compose run --rm backend alembic upgrade head
docker compose run --rm backend python -m app.bootstrap --email admin@example.org
docker compose up -d backend nginx
```

Migration and bootstrap commands intentionally write the selected database.
Check the environment and database identity before executing them. Bootstrap
prompts for a password (12–72 UTF-8 bytes), never accepts it as a command-line
argument, and refuses a nonempty users table. PostgreSQL advisory locking
serializes competing bootstrap attempts. This is not an account recovery tool.

No existing migrations are rewritten. Before upgrades, take and restore-test a
backup; review forward migrations against a copy of representative data. Do not
use destructive schema reset or assume a downgrade preserves data. Roll back
application images only when compatible with the applied database schema.

## Exposure and proxy trust

Only Nginx is published, on loopback port 8080 by default. A separately managed
TLS ingress must terminate HTTPS/WSS and reach that loopback listener before
external use. This repository does not provision certificates or cloud ingress.
Do not publish PostgreSQL, optional Redis, or the production backend. The private
backend trusts forwarded headers from its isolated deployment network; Nginx
overwrites X-Forwarded-For with its immediate peer. When adding another proxy,
configure its exact trusted addresses explicitly before trusting original IPs.
Do not attach untrusted containers to this network.

The server runs as UID 10001 without reload, with an explicit single worker and
WebSocket transport. Nginx forwards upgrade headers. URI access logging is
disabled because ingestion paths contain secrets and SSE supports query tokens.
Application diagnostic logs remain enabled; further telemetry hardening is
tracked separately. Image tags are version-family pinned, not immutable digests;
resolve and review deployment digests as part of the release process.

## Health

`/health` and `/api/v1/health` are cheap, DB-free liveness checks.
`/api/v1/ready` requires a reachable database at the application's Alembic head;
it returns 503 before migrations or when the database check fails. PostgreSQL
connections and statements have bounded three-second timeouts; connection pool
checkout is a separate resource bound and must be considered in load testing.

## Local development

```sh
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This explicitly enables reload, a read-only source mount, and a loopback backend
port. Migrate and bootstrap first as above. Do not use the development override
for external deployment. Redis is optional (`--profile optional-redis`), not a
required application startup dependency.

## Release evidence still required

Test migrations and bootstrap against disposable PostgreSQL, then validate
WebSocket and SSE through actual Uvicorn and Nginx. Test readiness during an
outage, restart behavior, backups/restores, and TLS ingress. A green TestClient
suite does not satisfy these gates. No Docker/network validation is implied by
the presence of this configuration.

## Identity migration and authentication compatibility

Migration `20260918_01` refuses legacy rows with unknown roles, tenant-bound
system administrators, or tenant users/admins without a tenant. Before deployment,
inspect these rows using a read-only query and establish the correct identity
with the owner. Do not silently promote, delete, or assign users to guessed
tenants. Resolve invalid records in an explicitly approved repair transaction,
then rerun the migration. Existing production data has not been inspected by
the implementation's disposable-database tests.

The migration adds an invalidation counter and database scope constraints;
legitimate existing roles remain VARCHAR-compatible. JWTs now require `sub`,
`exp`, and `ver`. Previously issued tokens without `ver` are intentionally
invalid: users must log in after deployment. Password, role, tenant, and active
state changes advance the counter. Roles and tenant permissions still come from
the database, never from JWT claims. An inactive tenant prevents normal member
authentication without permanently disabling member accounts. System-admin
global operations remain available.

Passwords above 72 UTF-8 bytes are rejected, never truncated. Existing shorter
password hashes remain valid; accounts previously using longer passwords need
an authorized reset. Login defaults to 30 attempts per source and 600 globally
per fixed 60-second window (configurable LOGIN_ATTEMPTS_PER_MINUTE and
LOGIN_GLOBAL_ATTEMPTS_PER_MINUTE); excess returns 429 with Retry-After. The
limiter holds at most 4096 source counters and is process-local. Boundaries can
admit bursts spanning adjacent windows; this is not distributed abuse defense.
Configure trusted proxy addresses correctly before relying on source IP limits.

Streaming uses these identity checks at connection time. Mid-connection
revocation and database-session lifetime are separate remediation work and must
not be inferred from this authentication change.
