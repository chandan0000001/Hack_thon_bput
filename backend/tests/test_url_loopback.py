"""Regression and unit tests for strict loopback/localhost allowlist (URL-LOOPBACK-ALLOWLIST).

Validates:
1. Strict loopback helper (is_strict_loopback) correctly validates loopback addresses
   and rejects lookalike domains (localhost.com, 127.0.0.1.evil.com) and private IP ranges.
2. ALLOWED cases return severity='low', action='allow', reason='loopback_localhost'
   when ALLOW_LOOPBACK_URLS=True.
3. DENIED cases go through standard analysis and are never allowed as loopback_localhost.
4. When ALLOW_LOOPBACK_URLS=False, even localhost undergoes normal analysis.
"""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.services.scoring_service import URL_ACTION_ALLOW, URL_ACTION_BLOCK, URL_ACTION_WARN
from app.services.url_analyzer import analyze_url
from app.utils.url_helpers import is_strict_loopback


class TestStrictLoopbackHelper:
    """L2: Verify is_strict_loopback handles loopbacks and strictly rejects non-loopbacks."""

    @pytest.mark.parametrize(
        "hostname",
        [
            "localhost",
            "LocalHost",
            "  localhost  ",
            "127.0.0.1",
            " 127.0.0.1 ",
            "127.0.0.2",
            "127.0.1.1",
            "::1",
            "[::1]",
        ],
    )
    def test_strict_loopback_valid_cases(self, hostname: str):
        assert is_strict_loopback(hostname) is True

    @pytest.mark.parametrize(
        "hostname",
        [
            "localhost.com",
            "localhost.evil.com",
            "localhost.example.com",
            "127.0.0.1.evil.com",
            "127.0.0.1.com",
            "10.0.0.1",
            "10.255.255.255",
            "192.168.1.1",
            "192.168.0.100",
            "172.16.0.1",
            "172.31.255.255",
            "8.8.8.8",
            "evil-localhost.com",
            "notlocalhost",
            "",
            "   ",
        ],
    )
    def test_strict_loopback_denied_cases(self, hostname: str):
        assert is_strict_loopback(hostname) is False

    def test_strict_loopback_handles_non_string_and_none(self):
        assert is_strict_loopback(None) is False  # type: ignore[arg-type]
        assert is_strict_loopback(127) is False  # type: ignore[arg-type]


class TestUrlLoopbackAllowlistAllowed:
    """L4: Test allowed cases with ALLOW_LOOPBACK_URLS=True."""

    @pytest.fixture(autouse=True)
    def enable_loopback_allowlist(self, monkeypatch):
        settings = get_settings()
        monkeypatch.setattr(settings, "ALLOW_LOOPBACK_URLS", True)

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:8000/login",
            "http://localhost:8000/api/test?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHvdPOv",
            "http://127.0.0.1",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:8000/api/test",
            "http://[::1]",
            "http://[::1]:8000",
        ],
    )
    def test_allowed_loopback_urls(self, url: str):
        result = analyze_url(url)
        assert result["severity"] == "low"
        assert result["action"] == "allow"
        assert result["reason"] == "loopback_localhost"
        assert result["risk_score"] == 0
        assert result["decision"]["action"] == URL_ACTION_ALLOW


class TestUrlLoopbackAllowlistDenied:
    """L4: Test denied cases must go through normal analysis and not be allowed as loopback."""

    @pytest.fixture(autouse=True)
    def enable_loopback_allowlist(self, monkeypatch):
        settings = get_settings()
        monkeypatch.setattr(settings, "ALLOW_LOOPBACK_URLS", True)

    @pytest.mark.parametrize(
        "url",
        [
            "https://localhost.com",
            "https://localhost.evil.com",
            "https://localhost.example.com",
            "https://127.0.0.1.evil.com",
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
        ],
    )
    def test_denied_urls_undergo_standard_analysis(self, url: str):
        result = analyze_url(url)
        # Reason must never be loopback_localhost
        assert result.get("reason") != "loopback_localhost"

    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "https://localhost.evil.com",
        ],
    )
    def test_denied_suspicious_urls_flagged_warn_or_block(self, url: str):
        result = analyze_url(url)
        assert result.get("reason") != "loopback_localhost"
        assert result["severity"] in ("medium", "high", "critical")
        assert result["action"] in (URL_ACTION_WARN, URL_ACTION_BLOCK)


class TestUrlLoopbackDisabledByDefault:
    """L4: Test that when ALLOW_LOOPBACK_URLS=False, even http://localhost goes through normal analysis."""

    def test_default_config_is_false(self):
        settings = get_settings()
        # Default MUST be False
        assert getattr(settings, "ALLOW_LOOPBACK_URLS", False) is False

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
        ],
    )
    def test_disabled_loopback_urls_undergo_normal_analysis(self, url: str, monkeypatch):
        settings = get_settings()
        monkeypatch.setattr(settings, "ALLOW_LOOPBACK_URLS", False)

        result = analyze_url(url)
        assert result.get("reason") != "loopback_localhost"
