"""DNS resolution layer for independent email-auth verification (AUTH-VERIFY).

Wraps dnspython behind a small, controlled API so SPF/DKIM/DMARC verification
gets:

- one timeout knob (``DNS_TIMEOUT_S``, default 3s) applied per query;
- an LRU cache capped at ``DNS_CACHE_MAX`` entries with a TTL bound, so the
  same record (SPF TXT, DKIM key, DMARC policy) is fetched once per TTL;
- a per-domain circuit breaker: N transport failures within a window open the
  breaker for that domain's base domain, failing fast while an outbound path
  or resolver is down;
- an offline mode (``DNS_OFFLINE=true``) that raises :class:`DNSUnavailable`
  immediately without touching the network — the test harness and air-gapped
  deployments rely on this;
- :class:`LookupBudget`, a hard cap on DNS lookups per SPF check (RFC 7208
  limits check_host() to 10 referencing mechanisms/modifiers).

Every failure surfaces as :class:`DNSUnavailable`; callers translate that into
"verification unavailable" — never into "verified pass".
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import OrderedDict, deque
from typing import Any, Callable, Optional

logger = logging.getLogger("cyberguard.auth.dns")

DNS_TRANSPORT = Callable[[str, str], list[str]]


class DNSUnavailable(Exception):
    """DNS could not be queried (offline mode, breaker open, transport error)."""


class LookupBudgetExceeded(Exception):
    """Raised when an SPF check would exceed its DNS lookup budget."""


class LookupBudget:
    """Hard cap on DNS lookups consumed by one verification (RFC 7208: 10)."""

    def __init__(self, max_lookups: int = 10):
        self.max_lookups = max_lookups
        self.used = 0

    def tick(self, what: str = "") -> None:
        self.used += 1
        if self.used > self.max_lookups:
            raise LookupBudgetExceeded(
                f"DNS lookup limit ({self.max_lookups}) exceeded"
                + (f" at {what}" if what else "")
            )


def base_domain(name: str) -> str:
    """Registrable-domain approximation (last two labels, minus common
    two-part public suffixes). Used to key the circuit breaker and to
    approximate DMARC organizational domains."""
    labels = [l for l in (name or "").lower().rstrip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels) if labels else ""
    two_part_tlds = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.nz",
        "com.au", "com.br", "com.mx", "com.tr", "com.cn", "co.za",
    }
    last_two = ".".join(labels[-2:])
    if last_two in two_part_tlds:
        return ".".join(labels[-3:])
    return last_two


def _dnspython_transport(timeout_s: float) -> DNS_TRANSPORT:
    """Build a transport around dnspython, or a stub that fails if missing."""
    try:
        import dns.resolver  # type: ignore
    except Exception:  # pragma: no cover - exercised only without dnspython
        def _missing(qname: str, rdtype: str) -> list[str]:
            raise DNSUnavailable("dnspython is not installed")
        return _missing

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout_s
    resolver.timeout = timeout_s

    def transport(qname: str, rdtype: str) -> list[str]:
        # NXDOMAIN / NoAnswer are VALID negative answers for SPF/DMARC/DKIM
        # key discovery — they return [] and must not trip the breaker.
        try:
            answers = resolver.resolve(qname, rdtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception as exc:
            raise DNSUnavailable(f"DNS transport failure for {qname}/{rdtype}: {exc}") from exc
        return [a.to_text() for a in answers if getattr(a, "strings", None) is not None or True]

    return transport


class DNSResolver:
    """Caching, breaker-guarded DNS resolver with an injectable transport.

    Tests inject ``transport`` (and optionally ``offline=True``) so the whole
    verification layer is exercised without any network I/O.
    """

    def __init__(
        self,
        *,
        timeout: Optional[float] = None,
        cache_max: Optional[int] = None,
        offline: Optional[bool] = None,
        transport: Optional[DNS_TRANSPORT] = None,
        default_ttl_s: float = 300.0,
        cb_failure_threshold: Optional[int] = None,
        cb_window_s: Optional[float] = None,
        cb_open_s: Optional[float] = None,
    ):
        from app.core.config import get_settings

        settings = get_settings()
        self.timeout = float(settings.DNS_TIMEOUT_S if timeout is None else timeout)
        self.cache_max = int(settings.DNS_CACHE_MAX if cache_max is None else cache_max)
        self.offline_configured = bool(settings.DNS_OFFLINE) if offline is None else bool(offline)
        self.default_ttl_s = default_ttl_s
        self.cb_failure_threshold = int(
            settings.DNS_CB_FAILURE_THRESHOLD if cb_failure_threshold is None else cb_failure_threshold
        )
        self.cb_window_s = float(settings.DNS_CB_WINDOW_S if cb_window_s is None else cb_window_s)
        self.cb_open_s = float(settings.DNS_CB_OPEN_S if cb_open_s is None else cb_open_s)

        self.uses_default_transport = transport is None
        self.transport: DNS_TRANSPORT = transport or _dnspython_transport(self.timeout)
        self.transport_calls = 0  # incremented on every real transport attempt

        self._cache: OrderedDict[tuple[str, str], tuple[float, list[str]]] = OrderedDict()
        self._failures: dict[str, deque[float]] = {}
        self._open_until: dict[str, float] = {}
        self._lock = threading.RLock()

    # -- state helpers ------------------------------------------------------

    @property
    def offline(self) -> bool:
        return self.offline_configured

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def reset_breaker(self, domain: Optional[str] = None) -> None:
        with self._lock:
            if domain is None:
                self._failures.clear()
                self._open_until.clear()
            else:
                self._failures.pop(domain, None)
                self._open_until.pop(domain, None)

    # -- core API -----------------------------------------------------------

    def resolve(self, qname: str, rdtype: str = "TXT") -> list[str]:
        """Resolve qname/rdtype; raises DNSUnavailable instead of throwing raw
        socket errors. Cached values are TTL-bounded and LRU-evicted."""
        key = (qname.lower().rstrip("."), rdtype.upper())
        domain = base_domain(key[0])
        now = time.monotonic()

        if self.offline:
            raise DNSUnavailable("DNS offline mode (DNS_OFFLINE=true)")

        with self._lock:
            open_until = self._open_until.get(domain)
            if open_until is not None and now < open_until:
                raise DNSUnavailable(
                    f"circuit breaker open for {domain} ({max(0.0, open_until - now):.0f}s remaining)"
                )
            hit = self._cache.get(key)
            if hit is not None:
                expires, values = hit
                if expires > now:
                    self._cache.move_to_end(key)
                    return list(values)
                self._cache.pop(key, None)

        values = self._query(qname, rdtype)

        with self._lock:
            self._cache[key] = (time.monotonic() + self.default_ttl_s, list(values))
            self._cache.move_to_end(key)
            while len(self._cache) > max(1, self.cache_max):
                self._cache.popitem(last=False)
        return list(values)

    async def resolve_async(self, qname: str, rdtype: str = "TXT") -> list[str]:
        return await asyncio.to_thread(self.resolve, qname, rdtype)

    def _query(self, qname: str, rdtype: str) -> list[str]:
        domain = base_domain(qname)
        self.transport_calls += 1
        try:
            values = self.transport(qname, rdtype) or []
        except DNSUnavailable:
            self._record_failure(domain)
            raise
        except Exception as exc:
            self._record_failure(domain)
            raise DNSUnavailable(f"DNS transport failure for {qname}/{rdtype}: {exc}") from exc
        with self._lock:
            self._failures.pop(domain, None)  # success closes the breaker window
        return values

    def _record_failure(self, domain: str) -> None:
        now = time.monotonic()
        with self._lock:
            window = self._failures.setdefault(domain, deque())
            window.append(now)
            while window and now - window[0] > self.cb_window_s:
                window.popleft()
            if len(window) >= self.cb_failure_threshold:
                self._open_until[domain] = now + self.cb_open_s
                window.clear()
                logger.warning("DNS circuit breaker OPEN for %s (%ss)", domain, self.cb_open_s)


# ---------------------------------------------------------------------------
# Default resolver singleton
# ---------------------------------------------------------------------------

_default_resolver: Optional[DNSResolver] = None
_default_lock = threading.Lock()


def get_default_resolver() -> DNSResolver:
    global _default_resolver
    with _default_lock:
        if _default_resolver is None:
            _default_resolver = DNSResolver()
        return _default_resolver


def set_default_resolver(resolver: Optional[DNSResolver]) -> None:
    """Swap the process-wide resolver (used by tests; None re-enables lazily
    building the default one)."""
    global _default_resolver
    with _default_lock:
        _default_resolver = resolver
