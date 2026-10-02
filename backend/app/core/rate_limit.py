"""Bounded rate limiting and admission control for HoneyShield.

CRITICAL ARCHITECTURAL CONCURRENCY NOTE:
----------------------------------------
PROCESS-LOCAL STATE ENFORCEMENT:
The rate limiters in this module maintain all state in-process memory, protected
by thread locks. In the standard HoneyShield single-process container deployment
(--workers 1), this provides comprehensive admission control across all threads
and async tasks within the process.

HOWEVER, THIS STATE IS NOT DISTRIBUTED:
If the application is deployed with multiple Uvicorn workers (--workers > 1) or
replicated across multiple container instances without sticky routing, each
worker process maintains its own independent rate limiter state buckets. True
cluster-wide distributed rate limiting requires an external coordinated state
store (such as Redis) and must be introduced in a future infrastructure phase.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional


class FixedWindowLimiter:
    """Thread-safe bounded fixed-window rate limiter for in-process admission control."""

    def __init__(
        self,
        max_keys: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the rate limiter with a maximum key capacity and clock source."""
        self._clock = clock
        self._max_keys = max_keys
        self._window: Optional[int] = None
        self._counts: dict[str, int] = {}
        self._total: int = 0
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, global_limit: int, window_seconds: int = 60) -> bool:
        """Evaluate whether a request key is within limits (backward-compatible)."""
        allowed, _ = self.check_and_increment(key, limit, global_limit, window_seconds=window_seconds)
        return allowed

    def check_and_increment(
        self,
        key: str,
        limit: int,
        global_limit: int,
        window_seconds: int = 60,
    ) -> tuple[bool, int]:
        """Check if request is allowed, record it if allowed, and return (allowed, retry_after).

        Args:
            key: Rate limit identifier (e.g., client IP, user ID, or composite key).
            limit: Maximum allowed requests for this key in the current window.
            global_limit: Maximum allowed requests across all keys in the current window.
            window_seconds: Duration of the rate-limiting window in seconds.

        Returns:
            A tuple of (is_allowed: bool, retry_after_seconds: int).
        """
        now = self._clock()
        current_window = int(now // window_seconds)
        # Calculate seconds remaining until the start of the next window
        seconds_into_window = now % window_seconds
        retry_after = max(1, int(window_seconds - seconds_into_window))

        with self._lock:
            if self._window != current_window:
                self._window = current_window
                self._counts.clear()
                self._total = 0

            # Check global threshold
            if self._total >= global_limit:
                return False, retry_after

            current_count = self._counts.get(key, 0)
            if current_count >= limit:
                return False, retry_after

            # Defend against memory exhaustion from high-cardinality attacker keys
            if key not in self._counts and len(self._counts) >= self._max_keys:
                return False, retry_after

            self._counts[key] = current_count + 1
            self._total += 1
            return True, 0

    def reset(self) -> None:
        """Reset all rate limiter counters to initial state (for testing / restart)."""
        with self._lock:
            self._window = None
            self._counts.clear()
            self._total = 0


# Shared process-local instances
login_limiter = FixedWindowLimiter(max_keys=4096)
api_limiter = FixedWindowLimiter(max_keys=8192)
ingestion_limiter = FixedWindowLimiter(max_keys=8192)


def reset_all_limiters() -> None:
    """Reset all active rate limiters across the application."""
    login_limiter.reset()
    api_limiter.reset()
    ingestion_limiter.reset()
