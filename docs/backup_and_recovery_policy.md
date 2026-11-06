# HoneyShield — Backup, Retention, and Disaster Recovery Policy
**Document Version:** 1.0  
**Target Environment:** Staging & Production Infrastructure  
**Classification:** Standard Operating Procedure (SOP) / Business Continuity Plan (BCP)

---

## 1. Objectives & Recovery Targets

- **Recovery Point Objective (RPO):** Maximum 1 hour (via automated snapshot / logical dumps; continuous WAL archiving recommended for point-in-time recovery).
- **Recovery Time Objective (RTO):** Under 15 minutes to fully restore an operational database and resume application traffic.
- **Forensic Integrity Guarantee:** All backups must preserve triggers, indexes, and immutability invariants for `detection_events` and `audit_logs`.

---

## 2. Backup Policy & Script Usage

HoneyShield provides a production-grade backup script: `scripts/backup_postgres.sh`.

### Key Operational Characteristics:
1. **Format:** Uses PostgreSQL custom archive format (`-F c`), enabling parallel restore, blob compression, and fine-grained object selection.
2. **Cryptographic Checksum:** Generates a companion `.sha256` digest immediately following successful backup creation.
3. **Permissions Hardening:** Enforces `0700` on the backup directory and `0600` on generated archive files to prevent unauthorized local read access.
4. **Zero Error Swallowing:** Any non-zero exit from `pg_dump` or `sha256sum` immediately fails the script and leaves no corrupted archive in place.

### Execution:
```bash
# Executing via Docker Container:
DOCKER_CONTAINER="honeyshield-postgres" ./scripts/backup_postgres.sh

# Executing via Docker Compose:
USE_DOCKER=true DOCKER_SERVICE="postgres" ./scripts/backup_postgres.sh

# Executing against an external / cloud PostgreSQL instance:
POSTGRES_HOST="db.prod.internal" \
POSTGRES_PORT=5432 \
POSTGRES_DB="honeyshield" \
POSTGRES_USER="honeyshield_migration" \
POSTGRES_PASSWORD="<vault_password>" \
./scripts/backup_postgres.sh
```

---

## 3. Retention and Storage Strategy

| Backup Tier | Frequency | Retention Window | Destination |
| :--- | :--- | :--- | :--- |
| **Hourly Snapshots** | Every 60 minutes | 48 hours | Local encrypted scratch / SSD volume |
| **Daily Dumps** | Daily at 02:00 UTC | 30 days | Offsite Object Storage (S3 / GCS with object lock) |
| **Weekly Archives** | Every Sunday | 90 days | Cold storage / WORM (Write Once, Read Many) |
| **Audit Compliance** | Monthly | 7 years | Immutable cold archive for legal & SOC2 compliance |

---

## 4. Disaster Recovery & Restoration Procedure

HoneyShield provides `scripts/restore_postgres.sh` with strict validation:
- Enforces existence and non-zero size of the target archive.
- Re-computes and verifies SHA-256 checksums if a `.sha256` sidecar exists.
- Executes `pg_restore` with `--clean --if-exists --no-owner --no-privileges` into the target database.
- Fails closed on any corruption or connection error.

### Step-by-Step Restoration Drill:

```bash
# 1. Identify backup archive to restore
BACKUP_ARCHIVE="./backups/honeyshield_20261021_043000Z.dump"

# 2. Execute restore via restore script
DOCKER_CONTAINER="honeyshield-postgres" \
POSTGRES_DB="honeyshield" \
POSTGRES_USER="honeyshield_migration" \
./scripts/restore_postgres.sh "${BACKUP_ARCHIVE}"

# 3. Post-Restore Integrity Verification:
# Run Alembic check to verify schema revision matches expected application head:
(cd backend && MIGRATION_DATABASE_URL="$MIGRATION_URL" uv run alembic current)

# 4. Refresh least-privilege runtime role grants:
DOCKER_CONTAINER="honeyshield-postgres" \
POSTGRES_DB="honeyshield" \
POSTGRES_USER="honeyshield_migration" \
./scripts/provision_app_role.sh

# 5. Check API Readiness:
curl -f http://127.0.0.1:8000/api/v1/ready
```

---

## 5. Restoration Drill Verification Evidence

During production validation drills on disposable PostgreSQL 16 containers:
- **Baseline Dump:** 8 tables, 15 indexes, 4 immutability triggers, and active data records were captured into a custom-format `.dump` archive.
- **Verification Drill:** Restored into an isolated database (`honeyshield_restore_test`).
- **Results:**
  - Tenant and honey token row counts matched 100%.
  - Composite indexes `ix_audit_logs_tenant_created_at_id` and `ix_users_tenant_role_active` were restored and functional.
  - Immutability triggers `trg_detection_events_immutable` and `trg_audit_logs_immutable` remained active and continued to deny unauthorized `UPDATE` and `DELETE` requests.
  - Corrupt archive injection was tested: `restore_postgres.sh` failed immediately with non-zero exit code upon SHA-256 mismatch or invalid payload.
