"""Header security, sanitization, and bounded forensic persistence."""
from __future__ import annotations

import json
from typing import Any, Mapping

# Strictly allowlisted headers with legitimate forensic / investigative value
ALLOWED_FORENSIC_HEADERS = frozenset({
    "user-agent",
    "referer",
    "accept",
    "accept-language",
    "accept-encoding",
    "origin",
    "host",
    "x-request-id",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
})

# Forbidden sensitive headers that must NEVER be persisted under any circumstance
FORBIDDEN_CREDENTIAL_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "jwt",
    "session",
})


def sanitize_forensic_headers(
    headers: Mapping[str, Any] | None,
    max_key_length: int = 64,
    max_value_length: int = 1024,
    max_count: int = 30,
    max_total_bytes: int = 4096,
) -> dict[str, str] | None:
    """Sanitize and bound HTTP headers before persisting into forensic records (F-013).

    Rules:
    1. Filter out all non-allowlisted headers and all credential-bearing headers.
    2. Normalize header keys to lowercase.
    3. Truncate header values deterministically to max_value_length.
    4. Cap total number of retained headers to max_count.
    5. Ensure total JSON representation does not exceed max_total_bytes.
    """
    if not headers or not isinstance(headers, Mapping):
        return None

    sanitized: dict[str, str] = {}
    count = 0

    for raw_k, raw_v in headers.items():
        if count >= max_count:
            break

        if not isinstance(raw_k, str):
            continue

        key = raw_k.strip().lower()
        if len(key) > max_key_length:
            continue

        # Strict credential defense
        if key in FORBIDDEN_CREDENTIAL_HEADERS:
            continue

        # Must be in the explicit forensic allowlist
        if key not in ALLOWED_FORENSIC_HEADERS:
            continue

        # Convert value to safe truncated string
        if raw_v is None:
            continue
        val_str = str(raw_v).strip()
        if len(val_str) > max_value_length:
            val_str = val_str[:max_value_length]

        sanitized[key] = val_str
        count += 1

    if not sanitized:
        return None

    # Check total JSON serialized size
    encoded = json.dumps(sanitized).encode("utf-8")
    if len(encoded) <= max_total_bytes:
        return sanitized

    # If serialized JSON exceeds max_total_bytes, deterministically prune least-critical headers
    # Priority order to retain: user-agent, referer, host, origin, sec-ch-ua, others
    priority_order = ["user-agent", "referer", "host", "origin", "sec-ch-ua"]
    pruned: dict[str, str] = {}
    for p_key in priority_order:
        if p_key in sanitized:
            pruned[p_key] = sanitized[p_key]

    # Further shorten values if still oversized
    while len(json.dumps(pruned).encode("utf-8")) > max_total_bytes and pruned:
        longest_k = max(pruned.keys(), key=lambda k: len(pruned[k]))
        if len(pruned[longest_k]) > 64:
            pruned[longest_k] = pruned[longest_k][: len(pruned[longest_k]) // 2]
        else:
            del pruned[longest_k]

    return pruned if pruned else None
