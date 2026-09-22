"""Firecrawl live page-scrape client (optional URL enrichment layer).

Mirrors the external-HTTP conventions of ``app.ai.llm_client``: a bounded
``httpx.AsyncClient``, masked-key structured logs, and graceful degradation —
this module NEVER raises. Every failure path (missing key, timeout, 4xx/5xx,
cache/Redis outage) returns ``None`` so the URL detection pipeline falls back
byte-identically to heuristics-only behaviour.

Responses are cached in Redis (keyed by ``sha256(url)``) for
``FIRECRAWL_CACHE_TTL_SECONDS`` and outbound calls are bounded by an
``asyncio.Semaphore(FIRECRAWL_MAX_CONCURRENCY)`` plus
``asyncio.wait_for(FIRECRAWL_TIMEOUT_SECONDS)``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.core.metrics import firecrawl_cache_hits_total, firecrawl_scrapes_total

logger = logging.getLogger("cyberguard.firecrawl")

_REDIS_KEY_PREFIX = "cyberguard:firecrawl:scrape:"
_RETRIABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_RETRY_BACKOFF_BASE_SECONDS = 0.5

_http_client: httpx.AsyncClient | None = None
_http_client_lock = asyncio.Lock()
_semaphore: asyncio.Semaphore | None = None
_semaphore_size: int = 0
_redis_client: object | None = None


@dataclass
class FirecrawlScrape:
    """Normalized scrape result from the Firecrawl /v2/scrape endpoint."""

    markdown: str = ""
    html: str = ""
    links: list[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    source_url: str = ""
    status_code: int = 0

    @classmethod
    def from_api_payload(cls, payload: dict) -> "FirecrawlScrape":
        """Parse a Firecrawl API response ``data`` object into a scrape."""
        data = payload.get("data") or {}
        metadata = data.get("metadata") or {}
        links = data.get("links") or []
        return cls(
            markdown=str(data.get("markdown") or ""),
            html=str(data.get("html") or ""),
            links=[str(link) for link in links if link],
            title=str(metadata.get("title") or ""),
            description=str(metadata.get("description") or ""),
            source_url=str(metadata.get("sourceURL") or metadata.get("sourceUrl") or ""),
            status_code=int(metadata.get("statusCode") or 0),
        )

    def to_cache_payload(self) -> str:
        """Serialize for the Redis cache (json blob)."""
        return json.dumps(
            {
                "markdown": self.markdown,
                "html": self.html,
                "links": self.links,
                "title": self.title,
                "description": self.description,
                "source_url": self.source_url,
                "status_code": self.status_code,
            }
        )

    @classmethod
    def from_cache_payload(cls, raw: str) -> "FirecrawlScrape | None":
        """Deserialize a cached scrape; returns ``None`` on malformed data."""
        try:
            blob = json.loads(raw)
            return cls(
                markdown=str(blob.get("markdown") or ""),
                html=str(blob.get("html") or ""),
                links=[str(link) for link in (blob.get("links") or []) if link],
                title=str(blob.get("title") or ""),
                description=str(blob.get("description") or ""),
                source_url=str(blob.get("source_url") or ""),
                status_code=int(blob.get("status_code") or 0),
            )
        except (ValueError, TypeError):
            return None

    def content_stats(self) -> dict[str, int]:
        """Sizes only — scraped HTML/markdown bodies are never logged."""
        return {
            "markdown_bytes": len(self.markdown),
            "html_bytes": len(self.html),
            "links": len(self.links),
        }


def masked_api_key(api_key: str) -> str:
    """Mask an API key for logging, e.g. ``fc-****1234``. Never log the raw key."""
    if not api_key:
        return "<unset>"
    tail = api_key[-4:] if len(api_key) >= 4 else api_key
    return f"****{tail}"


def _cache_key(url: str) -> str:
    """Redis cache key: sha256 of the exact submitted URL."""
    return _REDIS_KEY_PREFIX + hashlib.sha256(url.encode("utf-8")).hexdigest()


async def _get_http_client() -> httpx.AsyncClient:
    """Lazily create the shared bounded httpx client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        async with _http_client_lock:
            if _http_client is None or _http_client.is_closed:
                settings = get_settings()
                _http_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(settings.FIRECRAWL_TIMEOUT_SECONDS),
                    headers={"Authorization": f"Bearer {settings.FIRECRAWL_API_KEY}"},
                )
    return _http_client


def _get_semaphore() -> asyncio.Semaphore:
    """Semaphore bounding concurrent outbound scrapes (recreated if resized)."""
    global _semaphore, _semaphore_size
    settings = get_settings()
    if _semaphore is None or _semaphore_size != settings.FIRECRAWL_MAX_CONCURRENCY:
        _semaphore = asyncio.Semaphore(max(1, settings.FIRECRAWL_MAX_CONCURRENCY))
        _semaphore_size = settings.FIRECRAWL_MAX_CONCURRENCY
    return _semaphore


def _get_redis():
    """Lazily create the shared Redis client; returns ``None`` if unavailable.

    Injectable for tests via :func:`set_redis_client`.
    """
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        from redis.asyncio import Redis

        settings = get_settings()
        _redis_client = Redis.from_url(
            settings.REDIS_URL,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        )
        return _redis_client
    except Exception as exc:  # pragma: no cover - redis import/config failure
        logger.warning("Firecrawl Redis cache unavailable, continuing uncached: %s", exc)
        return None


def set_redis_client(client: object | None) -> None:
    """Test/ops hook: inject a Redis client (or ``None`` to force uncached)."""
    global _redis_client
    _redis_client = client


async def _cache_get(url: str) -> FirecrawlScrape | None:
    """Read a cached scrape; any Redis failure degrades to a cache miss."""
    client = _get_redis()
    if client is None:
        return None
    try:
        raw = await client.get(_cache_key(url))
    except Exception as exc:
        logger.warning("Firecrawl cache read failed (treating as miss): %s", exc)
        return None
    if not raw:
        return None
    firecrawl_cache_hits_total.inc()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    return FirecrawlScrape.from_cache_payload(raw)


async def _cache_set(url: str, scrape: FirecrawlScrape) -> None:
    """Write a cached scrape; cache failures are logged and ignored."""
    client = _get_redis()
    if client is None:
        return
    try:
        await client.set(
            _cache_key(url),
            scrape.to_cache_payload(),
            ex=get_settings().FIRECRAWL_CACHE_TTL_SECONDS,
        )
    except Exception as exc:
        logger.warning("Firecrawl cache write failed (ignoring): %s", exc)


async def _post_scrape(url: str) -> FirecrawlScrape | None:
    """Perform one (retried once) POST to Firecrawl /v2/scrape."""
    settings = get_settings()
    endpoint = settings.FIRECRAWL_BASE_URL.rstrip("/") + "/v2/scrape"
    body = {
        "url": url,
        "formats": ["markdown", "html", "links"],
        "onlyMainContent": False,
    }
    client = await _get_http_client()
    attempt = 0
    while True:
        attempt += 1
        try:
            async with _get_semaphore():
                response = await asyncio.wait_for(
                    client.post(endpoint, json=body),
                    timeout=settings.FIRECRAWL_TIMEOUT_SECONDS,
                )
        except (asyncio.TimeoutError, httpx.HTTPError) as exc:
            firecrawl_scrapes_total.labels(status="error").inc()
            logger.warning(
                "Firecrawl scrape attempt %d failed for host %s: %s",
                attempt,
                urlparse(url).hostname,
                type(exc).__name__,
            )
            if attempt >= 2 or not isinstance(exc, httpx.HTTPError):
                return None
            continue

        if response.status_code == 200:
            try:
                scrape = FirecrawlScrape.from_api_payload(response.json())
            except ValueError as exc:
                firecrawl_scrapes_total.labels(status="error").inc()
                logger.warning("Firecrawl returned non-JSON 200 payload: %s", exc)
                return None
            firecrawl_scrapes_total.labels(status="success").inc()
            logger.info(
                "Firecrawl scrape succeeded for host %s (upstream_status=%d): %s",
                urlparse(url).hostname,
                scrape.status_code,
                scrape.content_stats(),
            )
            return scrape

        firecrawl_scrapes_total.labels(
            status="rate_limited" if response.status_code == 429 else "http_error"
        ).inc()
        logger.warning(
            "Firecrawl scrape attempt %d returned HTTP %d (key=%s)",
            attempt,
            response.status_code,
            masked_api_key(get_settings().FIRECRAWL_API_KEY),
        )
        # ONE retry with jittered backoff on 429/5xx only.
        if response.status_code in _RETRIABLE_STATUS_CODES and attempt < 2:
            delay = _RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
            await asyncio.sleep(delay)
            continue
        return None


async def scrape_url(url: str) -> FirecrawlScrape | None:
    """Scrape ``url`` via Firecrawl, returning ``None`` on ANY failure.

    Degradation contract (never raises):
      * empty/unset ``FIRECRAWL_API_KEY`` or ``FIRECRAWL_ENABLED=False`` -> None
      * cache hit -> cached scrape (no outbound call)
      * timeout / connection error / non-recoverable HTTP status -> None
      * Redis outage -> proceeds uncached
    """
    settings = get_settings()
    if not settings.FIRECRAWL_ENABLED or not settings.FIRECRAWL_API_KEY:
        logger.info("Firecrawl enrichment disabled or key unset; skipping scrape.")
        return None

    cached = await _cache_get(url)
    if cached is not None:
        logger.info("Firecrawl cache hit for host %s: %s", urlparse(url).hostname, cached.content_stats())
        return cached

    try:
        scrape = await _post_scrape(url)
    except Exception as exc:  # last-resort guard: enrichment must never fail a scan
        firecrawl_scrapes_total.labels(status="error").inc()
        logger.warning("Firecrawl scrape raised unexpectedly; degrading to None: %s", exc)
        return None
    if scrape is not None:
        await _cache_set(url, scrape)
    return scrape


async def close_http_client() -> None:
    """Close the shared httpx client (call on app/worker shutdown)."""
    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()
    _http_client = None
