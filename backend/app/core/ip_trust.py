"""Secure client IP extraction, validation, and trusted-proxy handling."""
from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from fastapi import Request
    from app.core.config import Settings

logger = logging.getLogger(__name__)


def is_valid_ip(value: str) -> bool:
    """Check if a string represents a valid IPv4 or IPv6 address.

    Handles test environment loopbacks ('testclient' or 'localhost') appropriately.
    """
    if not value or not isinstance(value, str):
        return False
    val = value.strip()
    if val in ("testclient", "localhost"):
        return True
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def normalize_ip(value: str) -> str:
    """Parse and normalize an IP address to standard string form.

    Raises:
        ValueError: If value is not a valid IP address.
    """
    if not value or not isinstance(value, str):
        raise ValueError("IP address must be a non-empty string")
    val = value.strip()
    if val in ("testclient", "localhost"):
        return "127.0.0.1"
    try:
        obj = ipaddress.ip_address(val)
        return str(obj)
    except ValueError as e:
        raise ValueError(f"Invalid IP address format: '{val}'") from e


def is_ip_in_trusted_proxies(peer_ip: str, trusted_proxies: list[str]) -> bool:
    """Determine whether the peer IP address matches the trusted proxy configuration."""
    if not peer_ip:
        return False
    if "*" in trusted_proxies:
        return True

    # Normalize testclient / localhost
    if peer_ip in ("testclient", "localhost"):
        peer_ip = "127.0.0.1"

    try:
        peer_addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False

    for proxy_pattern in trusted_proxies:
        proxy_pattern = proxy_pattern.strip()
        if not proxy_pattern:
            continue
        try:
            if "/" in proxy_pattern:
                # CIDR network notation
                network = ipaddress.ip_network(proxy_pattern, strict=False)
                if peer_addr in network:
                    return True
            else:
                # Exact IP match
                target_addr = ipaddress.ip_address(proxy_pattern)
                if peer_addr == target_addr:
                    return True
        except ValueError:
            logger.warning("Invalid trusted proxy pattern configured: %s", proxy_pattern)
            continue

    return False


def extract_client_ip(request: "Request", settings: "Settings") -> str:
    """Extract and validate the client IP address according to the trusted proxy model.

    Security Rules:
    1. If the direct peer connection (request.client.host) is NOT in settings.trusted_proxies,
       all forwarding headers (X-Forwarded-For, X-Real-IP) are strictly IGNORED.
       This prevents spoofed forwarding headers from untrusted clients.
    2. If the direct peer IS in settings.trusted_proxies, X-Forwarded-For is evaluated
       (taking the rightmost untrusted or leftmost valid client IP) followed by X-Real-IP.
    3. If any extracted IP is malformed, falls back safely to the direct peer IP.
    4. Test environment 'testclient' is normalized to '127.0.0.1'.
    """
    raw_peer = request.client.host if request.client else None
    if not raw_peer:
        return "127.0.0.1"

    if raw_peer in ("testclient", "localhost"):
        peer_ip = "127.0.0.1"
    else:
        try:
            peer_ip = str(ipaddress.ip_address(raw_peer.strip()))
        except ValueError:
            return "127.0.0.1"

    # If the peer is not trusted to proxy traffic, use peer_ip directly.
    if not is_ip_in_trusted_proxies(peer_ip, settings.trusted_proxies):
        return peer_ip

    # Peer is a trusted proxy (e.g. Nginx or local container proxy)
    # Check X-Forwarded-For first
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        # X-Forwarded-For: client, proxy1, proxy2
        parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
        for candidate in parts:
            try:
                candidate_ip = str(ipaddress.ip_address(candidate))
                return candidate_ip
            except ValueError:
                continue

    # Check X-Real-IP
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        try:
            return str(ipaddress.ip_address(x_real_ip.strip()))
        except ValueError:
            pass

    return peer_ip
