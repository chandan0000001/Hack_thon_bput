"""In-memory token bucket rate limiter for user/job quotas."""

from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger("cyberguard.rate_limit")

# Default Gmail API quota: 250 requests/user/second
DEFAULT_CAPACITY = 250.0
DEFAULT_REFILL_RATE = 250.0
DEFAULT_DEFER_SECONDS = 5


class TokenBucketRateLimiter:
    """In-memory token bucket per (owner_user_id, job_type)."""

    def __init__(
        self,
        capacity: float = DEFAULT_CAPACITY,
        refill_rate: float = DEFAULT_REFILL_RATE,
        default_defer_seconds: int = DEFAULT_DEFER_SECONDS,
    ):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.default_defer_seconds = default_defer_seconds
        # key: (owner_user_id, job_type) -> [tokens, last_update_time]
        self._buckets: dict[tuple[str, str], list[float]] = {}

    def acquire(self, owner_user_id: str, job_type: str = "gmail_sync") -> int:
        """Attempt to consume 1 token.

        Returns:
            0 if token acquired immediately.
            defer_by (e.g. 5 seconds) if bucket exhausted.
        """
        now = time.monotonic()
        key = (owner_user_id, job_type)

        if key not in self._buckets:
            self._buckets[key] = [self.capacity - 1.0, now]
            return 0

        tokens, last_update = self._buckets[key]
        elapsed = now - last_update
        tokens = min(self.capacity, tokens + elapsed * self.refill_rate)

        if tokens >= 1.0:
            self._buckets[key] = [tokens - 1.0, now]
            return 0

        # Bucket empty -> rate limited
        self._buckets[key] = [tokens, now]
        logger.warning(
            "Rate limit triggered for user %s (job_type=%s, tokens_remaining=%.2f). Deferring by %ds",
            owner_user_id,
            job_type,
            tokens,
            self.default_defer_seconds,
        )
        return self.default_defer_seconds

    def reset(self) -> None:
        """Clear all bucket states."""
        self._buckets.clear()


_default_rate_limiter: Optional[TokenBucketRateLimiter] = None


def get_rate_limiter() -> TokenBucketRateLimiter:
    """Return the global TokenBucketRateLimiter singleton."""
    global _default_rate_limiter
    if _default_rate_limiter is None:
        _default_rate_limiter = TokenBucketRateLimiter()
    return _default_rate_limiter


class PerUserHTTPRateLimiter:
    """Token bucket for HTTP endpoints, keyed by authenticated principal id.

    Unlike the Gmail job limiter (which defers), this one answers a boolean:
    the API layer converts a miss into HTTP 429. In-memory by design — it
    guards a single API process; a multi-replica deploy should front it with
    a shared limiter (Redis) and keep this as per-replica backstop.
    """

    def __init__(self, rate_per_minute: float = 60.0, burst: int = 15):
        self.capacity = float(max(burst, 1))
        self.refill_rate = float(rate_per_minute) / 60.0
        self._buckets: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            self._buckets[key] = [self.capacity - 1.0, now]
            return True
        tokens, last = bucket
        tokens = min(self.capacity, tokens + (now - last) * self.refill_rate)
        if tokens >= 1.0:
            self._buckets[key] = [tokens - 1.0, now]
            return True
        self._buckets[key] = [tokens, now]
        return False


# Expensive analysis endpoints (URL engine: heuristics + enrichment + ML).
URL_ANALYSIS_RATE_PER_MINUTE = 60
URL_ANALYSIS_BURST = 15

_url_analysis_limiter: Optional[PerUserHTTPRateLimiter] = None


def get_url_analysis_limiter() -> PerUserHTTPRateLimiter:
    global _url_analysis_limiter
    if _url_analysis_limiter is None:
        _url_analysis_limiter = PerUserHTTPRateLimiter(
            rate_per_minute=URL_ANALYSIS_RATE_PER_MINUTE, burst=URL_ANALYSIS_BURST
        )
    return _url_analysis_limiter
