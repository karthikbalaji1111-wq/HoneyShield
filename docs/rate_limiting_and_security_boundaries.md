# HoneyShield — Rate Limiting Architecture & Security Boundaries
**Document Version:** 1.0  
**Target Environment:** Container Runtime & Ingress  
**Classification:** Architecture Specification & Threat Model

---

## 1. Admission Control & Rate Limiting Architecture

HoneyShield implements an in-memory, thread-safe admission control subsystem centered around `FixedWindowLimiter` (`backend/app/core/rate_limit.py`).

### Key Dimensions & Quotas:
| Category | Metric / Key | Default Quota | Behavior upon Exceeded Limit |
| :--- | :--- | :--- | :--- |
| **Authenticated API** | `user_id:<ID>` | 300 req / min | 429 Too Many Requests (`Retry-After: <secs>`) |
| **Public / Anonymous API** | `public_ip:<IP>` | 120 req / min | 429 Too Many Requests (`Retry-After: <secs>`) |
| **Global API Threshold** | Total requests in window | 5000 req / min | 429 Too Many Requests |
| **Login Protection** | `login_ip:<IP>` | 30 req / min | 429 Too Many Requests |
| **Token Ingestion** | `token:<VALUE>` | 60 req / min | 429 Too Many Requests |
| **Ingestion IP** | `ingestion_ip:<IP>` | 120 req / min | 429 Too Many Requests |

---

## 2. Memory Bounds & Fail-Closed Saturation Policy

### Bounded Memory Guarantees
To prevent adversarial memory exhaustion (e.g. an attacker distributing requests across millions of spoofed IP addresses or random bearer tokens):
1. **Maximum Key Capacity (`max_keys = 4096`):**
   The internal dictionary maintains at most 4096 tracking keys per limiter instance.
2. **Fail-Closed Admission:**
   If the dictionary reaches `max_keys` within an active 60-second window, any *new, untracked* key is immediately rejected (`429 Too Many Requests`) with a valid `Retry-After` header.
3. **Preservation of Existing Clients (No Key Eviction):**
   Existing clients already in the dictionary are NOT evicted. They continue to be serviced up to their individual quota limits.
4. **Deterministic Time-Window Reclamation:**
   At the rollover of the window (`time.monotonic() // window_seconds`), the dictionary is atomically cleared (`self._counts.clear()`), restoring capacity for all keys.

### Memory Overhead Bound:
- 4096 keys $\times$ ~100 bytes/entry $\approx$ ~400 KB of RAM maximum. Memory consumption cannot grow unbounded under denial-of-service attacks.

---

## 3. Cryptographic Token Pre-Verification Invariant

A common architectural vulnerability in rate limiting is granting elevated authenticated quotas based solely on the presence of an `Authorization: Bearer <token>` header without cryptographic verification.

In HoneyShield (`backend/app/middleware/rate_limit.py`):
1. The middleware parses `Authorization: Bearer <token>`.
2. It performs cryptographic signature verification and expiration checking using `jwt.decode(..., algorithms=["HS256"])` with `settings.jwt_secret_key`.
3. **If signature verification fails:** The client is NOT granted the authenticated bucket (300/min). It is demoted to the `public_ip:<IP>` bucket (120/min).
4. **Key Table Defense:** An attacker sending random/forged tokens from a single IP will all map to a single `public_ip:<IP>` bucket, completely neutralizing attempts to saturate the 4096-key capacity with fake tokens.

---

## 4. Single-Worker vs Distributed Architectural Boundary

> [!IMPORTANT]
> **Process-Local State Limitation:**
> In the standard single-process HoneyShield container (`--workers 1`), `FixedWindowLimiter` provides complete thread-safe admission control.
>
> However, if the deployment scales to multiple Uvicorn workers (`--workers > 1`) or multiple container replicas without sticky session routing, each worker process maintains independent counter buckets in its local heap.
>
> **Future Work:** Distributed multi-container deployments should configure an external Redis backend for cluster-wide rate limit synchronization.

---

## 5. Forensic Immutability Security Boundary

HoneyShield implements defense-in-depth for forensic records (`detection_events` and `audit_logs`):

1. **Layer 1: PostgreSQL Trigger Invariants:**
   PostgreSQL `BEFORE UPDATE`, `BEFORE DELETE`, and `BEFORE TRUNCATE` triggers (`prevent_forensic_modification()`) unconditionally raise exceptions for any mutation.
2. **Layer 2: SQL Table Grants (Principle of Least Privilege):**
   The runtime database role (`honeyshield_app`) only possesses `SELECT` and `INSERT` grants on forensic tables. `UPDATE`, `DELETE`, and `TRUNCATE` are denied at the SQL permission layer.
3. **Layer 3: Non-Owner Table Restriction:**
   Because `honeyshield_app` does not own the forensic tables, it is prohibited by PostgreSQL from running `ALTER TABLE detection_events DISABLE TRIGGER ALL`.
