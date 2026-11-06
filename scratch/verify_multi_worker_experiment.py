"""Controlled experiment demonstrating process-local limitation under multi-worker configuration."""
from __future__ import annotations

import multiprocessing
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

def run_experiment():
    print("=" * 60)
    print("STARTING PART 5: MULTI-WORKER PROCESS-LOCAL LIMITER EXPERIMENT")
    print("=" * 60)

    # Launch uvicorn with --workers 2 on port 8002
    env = dict(os.environ)
    env["PYTHONPATH"] = "."
    env["JWT_SECRET_KEY"] = "test-secret-key-for-honeyshield-at-least-32-bytes"
    env["RATE_LIMIT_PER_MINUTE_PUBLIC"] = "4"  # Set public limit to 4 req/min

    cmd = [
        sys.executable, "-m", "uvicorn",
        "app.main:app",
        "--host", "127.0.0.1",
        "--port", "8002",
        "--workers", "2",
        "--no-access-log"
    ]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2.5)  # Wait for workers to fork and start

    url = "http://127.0.0.1:8002/api/v1/health"  # Note: /api/v1/health is exempt, let's use an unauthenticated API endpoint
    target_url = "http://127.0.0.1:8002/api/v1/tenants/999"

    print("Sending 8 sequential requests to uvicorn with --workers 2 (limit configured = 4)...")
    results = []
    for i in range(1, 9):
        try:
            req = urllib.request.Request(target_url)
            with urllib.request.urlopen(req) as resp:
                results.append((i, resp.status))
        except urllib.error.HTTPError as e:
            results.append((i, e.code))

    proc.terminate()
    proc.wait()

    print(f"Results of 8 requests: {results}")
    status_codes = [status for _, status in results]
    success_count = sum(1 for s in status_codes if s in (401, 404))
    throttled_count = sum(1 for s in status_codes if s == 429)

    print(f"Admitted requests: {success_count}, Throttled (429): {throttled_count}")
    print("Empirical observation:")
    if success_count > 4:
        print("[PROVEN] With --workers 2, more than 4 requests were admitted because each worker maintains independent process-local counter buckets.")
    else:
        print(f"[OBSERVED] Handled by workers with counts: admitted={success_count}, throttled={throttled_count}")

    print("=" * 60)

if __name__ == "__main__":
    run_experiment()
