"""Tests for the Firecrawl client (Requirement E).

Covers: 200 / 429 / 500 mock transports, missing-key degradation, Redis cache
hit/miss, semaphore concurrency bound, and the timeout path — all offline via
``httpx.MockTransport`` and an in-memory cache stub. The client must NEVER
raise: every failure path returns ``None``.
"""

from __future__ import annotations

import asyncio
import hashlib

import httpx
import pytest

from app.core.config import get_settings
from app.services import firecrawl_client
from app.services.firecrawl_client import FirecrawlScrape, masked_api_key, scrape_url


class _MemoryRedis:
    """Minimal async Redis stand-in (no fakeredis dependency)."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.set_calls = 0

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.set_calls += 1
        self.store[key] = value


def _api_payload() -> dict:
    return {
        "data": {
            "markdown": "# Welcome to ExampleCo",
            "html": "<html><body><input type='text'><input type='password'></body></html>",
            "links": ["https://example.com/next"],
            "metadata": {
                "title": "ExampleCo Home",
                "description": "A perfectly ordinary page",
                "sourceURL": "https://example.com/",
                "statusCode": 200,
            },
        }
    }


def _cache_key(url: str) -> str:
    return "cyberguard:firecrawl:scrape:" + hashlib.sha256(url.encode()).hexdigest()


@pytest.fixture(autouse=True)
def _isolate_globals(monkeypatch: pytest.MonkeyPatch):
    """Reset module globals between tests; never touch a real Redis instance."""
    fresh_cache = _MemoryRedis()
    monkeypatch.setattr(firecrawl_client, "_redis_client", fresh_cache)
    monkeypatch.setattr(firecrawl_client, "_http_client", None)
    yield
    firecrawl_client._http_client = None
    firecrawl_client._redis_client = None


@pytest.fixture
def key_enabled(monkeypatch: pytest.MonkeyPatch):
    """Simulate an enabled Firecrawl configuration."""
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "fc-test1234", raising=False)
    monkeypatch.setattr(settings, "FIRECRAWL_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "FIRECRAWL_TIMEOUT_SECONDS", 2, raising=False)
    return settings


@pytest.mark.asyncio
async def test_scrape_200_parses_fields(key_enabled, monkeypatch: pytest.MonkeyPatch):
    seen_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers["authorization"] = request.headers.get("authorization", "")
        return httpx.Response(200, json=_api_payload())

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": f"Bearer {get_settings().FIRECRAWL_API_KEY}"},
    )
    monkeypatch.setattr(firecrawl_client, "_get_http_client", lambda: _async_return(client))
    scrape = await scrape_url("https://example.com/")
    assert scrape is not None
    assert scrape.title == "ExampleCo Home"
    assert scrape.markdown.startswith("# Welcome")
    assert "password" in scrape.html
    assert scrape.links == ["https://example.com/next"]
    assert scrape.source_url == "https://example.com/"
    assert scrape.status_code == 200
    assert seen_headers["authorization"] == "Bearer fc-test1234"


@pytest.mark.asyncio
async def test_scrape_429_retries_once_then_none(key_enabled, monkeypatch: pytest.MonkeyPatch):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, json={"error": "rate limited"})

    monkeypatch.setattr(firecrawl_client, "_RETRY_BACKOFF_BASE_SECONDS", 0.0)
    monkeypatch.setattr(
        firecrawl_client, "_get_http_client",
        lambda: _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    assert await scrape_url("https://example.com/") is None
    assert calls["n"] == 2  # exactly ONE retry


@pytest.mark.asyncio
async def test_scrape_500_retries_then_none(key_enabled, monkeypatch: pytest.MonkeyPatch):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500, json={"error": "boom"})

    monkeypatch.setattr(firecrawl_client, "_RETRY_BACKOFF_BASE_SECONDS", 0.0)
    monkeypatch.setattr(
        firecrawl_client, "_get_http_client",
        lambda: _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    assert await scrape_url("https://example.com/") is None
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_missing_key_degrades_to_none(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "", raising=False)
    monkeypatch.setattr(settings, "FIRECRAWL_ENABLED", True, raising=False)

    def handler(request: httpx.Request) -> httpx.Response:  # must never be called
        raise AssertionError("no outbound call allowed without an API key")

    monkeypatch.setattr(
        firecrawl_client, "_get_http_client",
        lambda: _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    assert await scrape_url("https://example.com/") is None


@pytest.mark.asyncio
async def test_disabled_flag_degrades_to_none(key_enabled, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(key_enabled, "FIRECRAWL_ENABLED", False, raising=False)
    assert await scrape_url("https://example.com/") is None


@pytest.mark.asyncio
async def test_cache_hit_skips_outbound_call(key_enabled, monkeypatch: pytest.MonkeyPatch):
    redis = _MemoryRedis()
    redis.store[_cache_key("https://example.com/")] = FirecrawlScrape(
        markdown="cached", title="Cached Title"
    ).to_cache_payload()
    monkeypatch.setattr(firecrawl_client, "_redis_client", redis)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("cache hit must not trigger an outbound call")

    monkeypatch.setattr(
        firecrawl_client, "_get_http_client",
        lambda: _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    scrape = await scrape_url("https://example.com/")
    assert scrape is not None and scrape.title == "Cached Title"


@pytest.mark.asyncio
async def test_cache_miss_then_write(key_enabled, monkeypatch: pytest.MonkeyPatch):
    redis = _MemoryRedis()
    monkeypatch.setattr(firecrawl_client, "_redis_client", redis)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_api_payload())

    monkeypatch.setattr(
        firecrawl_client, "_get_http_client",
        lambda: _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    scrape = await scrape_url("https://example.com/")
    assert scrape is not None
    assert redis.set_calls == 1
    assert _cache_key("https://example.com/") in redis.store
    # Second call served from cache.
    again = await scrape_url("https://example.com/")
    assert again is not None and again.title == scrape.title
    assert redis.set_calls == 1


@pytest.mark.asyncio
async def test_semaphore_bounds_concurrency(key_enabled, monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_MAX_CONCURRENCY", 2, raising=False)
    active = {"n": 0, "max": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        active["n"] += 1
        active["max"] = max(active["max"], active["n"])
        await asyncio.sleep(0.05)
        active["n"] -= 1
        return httpx.Response(200, json=_api_payload())

    def slow_client() -> object:
        return _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    monkeypatch.setattr(firecrawl_client, "_get_http_client", slow_client)
    await asyncio.gather(*(scrape_url(f"https://example.com/{i}") for i in range(6)))
    assert active["max"] <= 2


@pytest.mark.asyncio
async def test_timeout_path_returns_none(key_enabled, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(key_enabled, "FIRECRAWL_TIMEOUT_SECONDS", 1, raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated connect timeout", request=request)

    monkeypatch.setattr(
        firecrawl_client, "_get_http_client",
        lambda: _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    assert await scrape_url("https://example.com/") is None


@pytest.mark.asyncio
async def test_redis_outage_degrades_to_uncached_success(
    key_enabled, monkeypatch: pytest.MonkeyPatch
):
    class _BrokenRedis:
        async def get(self, key: str) -> str | None:
            raise ConnectionError("redis down")

        async def set(self, key: str, value: str, ex: int | None = None) -> None:
            raise ConnectionError("redis down")

    monkeypatch.setattr(firecrawl_client, "_redis_client", _BrokenRedis())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_api_payload())

    monkeypatch.setattr(
        firecrawl_client, "_get_http_client",
        lambda: _async_return(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
    )
    scrape = await scrape_url("https://example.com/")
    assert scrape is not None and scrape.title == "ExampleCo Home"


def test_masked_api_key_never_exposes_full_key():
    assert masked_api_key("fc-abcdef123456") == "****3456"
    assert masked_api_key("") == "<unset>"


def _async_return(value):
    future: asyncio.Future = asyncio.get_event_loop().create_future()
    future.set_result(value)
    return future
