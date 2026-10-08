"""URL validation and helper utilities (URL-LOOPBACK-ALLOWLIST)."""

from __future__ import annotations

import ipaddress


def is_strict_loopback(hostname: str) -> bool:
    """Determine whether a given hostname is strictly a loopback address or localhost.

    Rules:
    1. Normalize: hostname = hostname.lower().strip()
    2. Exact string match for "localhost".
    3. Exact string match for "127.0.0.1".
    4. Exact string match for "::1" or "[::1]".
    5. Use Python's ipaddress module: try: return ipaddress.ip_address(hostname.strip('[]')).is_loopback except ValueError: return False.

    Guarantees:
    - "localhost.com", "localhost.evil.com", "127.0.0.1.evil.com" return False.
    - Non-loopback private IPs (10.x, 192.168.x, 172.16.x) return False.
    """
    if not hostname or not isinstance(hostname, str):
        return False

    # 1. Normalize
    hostname = hostname.lower().strip()

    # 2. Exact string match for "localhost"
    if hostname == "localhost":
        return True

    # 3. Exact string match for "127.0.0.1"
    if hostname == "127.0.0.1":
        return True

    # 4. Exact string match for "::1" or "[::1]"
    if hostname in ("::1", "[::1]"):
        return True

    # 5. Use Python's ipaddress module for loopback evaluation
    try:
        return ipaddress.ip_address(hostname.strip("[]")).is_loopback
    except ValueError:
        return False
