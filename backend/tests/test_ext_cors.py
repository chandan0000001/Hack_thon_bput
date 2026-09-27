"""
EXT-P1: browser-extension CORS allow list.

The popup (an extension page) calls GET /auth/me directly, so
chrome-extension:// / moz-extension:// origins must be accepted by
CORSMiddleware. EXT_CORS_ORIGINS extends the base CORS_ORIGINS allow list
without touching website origins.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.core.config import Settings

# Pinned by browser-extension/build.mjs (stable unpacked key).
CHROMIUM_DEV_ORIGIN = "chrome-extension://mkhcpikficaipogflekjkoiplegbeaji"
FIREFOX_DEV_ORIGIN = "moz-extension://11111111-2222-3333-4444-555555555555"


def _settings_with_ext(**overrides) -> Settings:
    fields = dict(
        SUPABASE_URL="https://test.supabase.co",
        SUPABASE_ANON_KEY="test-anon-key",
        SUPABASE_SERVICE_ROLE_KEY="test-service-key",
        CORS_ORIGINS="http://localhost:5173,http://localhost:3000",
        EXT_CORS_ORIGINS=f"{CHROMIUM_DEV_ORIGIN},{FIREFOX_DEV_ORIGIN}",
        TEST_MODE=True,
        TEST_DATABASE_URL="postgresql+asyncpg://test:test@localhost:5432/test",
        TEST_REDIS_URL="redis://localhost:6379/1",
        _env_file=None,
    )
    fields.update(overrides)
    return Settings(**fields)


def _preflight_client(allow_origins: list[str]) -> TestClient:
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/ping")
    def ping():
        return {"ok": True}

    return TestClient(app)


def test_56_01_ext_cors_origins_merged_into_allow_list():
    """EXT_CORS_ORIGINS appends extension origins to the website list."""
    settings = _settings_with_ext()
    origins = settings.cors_origins_list
    assert CHROMIUM_DEV_ORIGIN in origins
    assert FIREFOX_DEV_ORIGIN in origins
    # Website origins must survive the merge.
    assert "http://localhost:5173" in origins
    assert "http://localhost:3000" in origins


def test_56_02_ext_cors_origins_default_empty_keeps_website_list():
    """No EXT_CORS_ORIGINS configured -> behaviour identical to before."""
    settings = _settings_with_ext(EXT_CORS_ORIGINS="")
    assert settings.cors_origins_list == ["http://localhost:5173", "http://localhost:3000"]


def test_56_03_extension_origin_preflight_allowed_and_unknown_rejected():
    """Preflight from a pinned extension origin is reflected; strangers are not."""
    settings = _settings_with_ext()
    client = _preflight_client(settings.cors_origins_list)

    res = client.options(
        "/ping",
        headers={
            "Origin": CHROMIUM_DEV_ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == CHROMIUM_DEV_ORIGIN

    res = client.options(
        "/ping",
        headers={
            "Origin": "chrome-extension://aaaaaaaaaaaaaaaa",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") != "chrome-extension://aaaaaaaaaaaaaaaa"
