# HoneyShield — Production Database Migration Runbook
**Document Version:** 1.0  
**Target Environment:** Staging & Production PostgreSQL 16+  
**Classification:** Standard Operating Procedure (SOP) / Reliability Engineering

---

## 1. Overview & Architectural Principles

HoneyShield enforces strict separation of duties between the database migration pipeline and the application runtime:
- **Migration Owner Role (`honeyshield_migration` or `POSTGRES_USER`):** Owns all database objects, executes DDL, creates indexes, and configures triggers.
- **Runtime Application Role (`honeyshield_app`):** Unprivileged role used by the FastAPI backend. It possesses only granular CRUD permissions on mutable tables and `SELECT/INSERT` only on forensic tables (`detection_events`, `audit_logs`). It cannot modify schema, drop tables, or disable immutability triggers.

### Migration Chain Architecture
HoneyShield maintains a strictly linear, single-head Alembic revision graph across 8 revisions:
```
241248046477 (Initial schema)
      ↓
4a30adb30e8f (Application configuration)
      ↓
e13aaeedde6d (Index optimizations)
      ↓
a3f1c9d28b74 (Threat intelligence structures)
      ↓
0214dbf0f07f (User management & AuditLog actor_user_id)
      ↓
20260918_01  (Identity invariants & session invalidation counter)
      ↓
20261002_01  (Composite B-Tree indexes on users & audit_logs)
      ↓
20261019_01  (Forensic immutability triggers for audit & detection) [HEAD]
```

---

## 2. Preflight Checklist (Mandatory Pre-Migration Gate)

Before running migrations against any staging or production database, execute the following preflight checks:

1. **Active Database Backup:**
   Execute a full custom-format dump with cryptographic SHA-256 verification:
   ```bash
   ./scripts/backup_postgres.sh
   ```
   Verify that the `.dump` and `.dump.sha256` files exist and permissions are `0600`.

2. **Verify Current Migration State:**
   Ensure current revision matches expectations without head divergence:
   ```bash
   (cd backend && MIGRATION_DATABASE_URL="$MIGRATION_URL" uv run alembic current)
   ```

3. **Check for Long-Running Transactions or Locks:**
   Query `pg_stat_activity` to ensure no blocking transactions hold exclusive table locks:
   ```sql
   SELECT pid, now() - xact_start AS duration, query, state
   FROM pg_stat_activity
   WHERE (now() - xact_start) > interval '1 minute'
     AND state != 'idle';
   ```

4. **Offline SQL Generation (Dry-Run):**
   Generate and visually review the exact SQL diff that will be executed:
   ```bash
   (cd backend && MIGRATION_DATABASE_URL="$MIGRATION_URL" uv run alembic upgrade <target_rev> --sql)
   ```

---

## 3. Migration Execution Procedure

### Step 1: Drain or Quiesce Ingestion (Recommended for Zero-Downtime)
For minor schema additions, HoneyShield supports rolling migrations. For migrations altering triggers or constraints, ensure traffic is routed to active maintenance or ingestion buffers.

### Step 2: Execute Migration as Migration Owner
Run Alembic pointing to the migration connection string:
```bash
MIGRATION_DATABASE_URL="postgresql+psycopg2://${POSTGRES_MIGRATION_USER}:${POSTGRES_MIGRATION_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}" \
PYTHONPATH=backend \
uv run --with-requirements backend/requirements.txt alembic -c backend/alembic.ini upgrade head
```

### Step 3: Re-Apply Least-Privilege Grants to Runtime Role
Whenever migrations introduce new tables or sequences, ensure the unprivileged runtime role permissions are refreshed:
```bash
POSTGRES_HOST="${POSTGRES_HOST}" \
POSTGRES_PORT="${POSTGRES_PORT}" \
POSTGRES_DB="${POSTGRES_DB}" \
POSTGRES_USER="${POSTGRES_MIGRATION_USER}" \
POSTGRES_PASSWORD="${POSTGRES_MIGRATION_PASSWORD}" \
POSTGRES_APP_USER="${POSTGRES_APP_USER}" \
./scripts/provision_app_role.sh
```

### Step 4: Verify Post-Migration Readiness
Query the backend readiness endpoint:
```bash
curl -f http://127.0.0.1:8000/api/v1/ready
# Expected: {"status":"ready","database":"connected","alembic_head":"20261019_01"}
```

---

## 4. Rollback and Downgrade Policy

> [!WARNING]
> Database downgrades that drop columns or tables permanently destroy data. Downgrades should only be attempted during emergency deployment aborts before new production data has accumulated.

### Rollback Step:
To revert to a previous revision:
```bash
(cd backend && MIGRATION_DATABASE_URL="$MIGRATION_URL" uv run alembic downgrade <previous_rev>)
```

### If Rollback Fails or Incurs Data Corruption:
1. Stop backend services immediately:
   ```bash
   docker compose stop backend
   ```
2. Restore the pre-migration backup using the verified recovery script:
   ```bash
   ./scripts/restore_postgres.sh ./backups/honeyshield_<TIMESTAMP>.dump
   ```
3. Restart backend services and verify readiness:
   ```bash
   docker compose up -d backend
   curl -f http://127.0.0.1:8000/api/v1/ready
   ```
