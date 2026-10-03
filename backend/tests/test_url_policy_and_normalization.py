"""Tests for the URL decision policy, shared normalization, and rate limiting.

Covers the "one engine, two entry points" requirements:
  * URL normalization is canonical and evidence-preserving (no decoding,
    no slash collapsing, punycode kept)
  * score -> verdict/action policy is explicit and monotone (HIGH only
    blocks with high ML confidence; CRITICAL always blocks)
  * per-user HTTP rate limiting for the expensive analysis endpoints
"""

import pytest

from app.core.rate_limit import PerUserHTTPRateLimiter
from app.core.url_normalization import normalize_url, normalization_pair
from app.services.scoring_service import (
    URL_ACTION_ALLOW,
    URL_ACTION_BLOCK,
    URL_ACTION_WARN,
    URL_VERDICT_MALICIOUS,
    URL_VERDICT_SAFE,
    URL_VERDICT_SUSPICIOUS,
    get_url_decision,
)


# ---------------------------------------------------------------------------
# Normalization (evidence-preserving canonical form)
# ---------------------------------------------------------------------------

def test_normalize_lowercases_host_and_strips_trailing_dot():
    assert normalize_url("HTTPS://EXAMPLE.COM./a") == "https://example.com/a"


def test_normalize_drops_default_port_only():
    assert normalize_url("https://example.com:443/login") == "https://example.com/login"
    assert normalize_url("http://example.com:80/") == "http://example.com/"
    # Non-default ports are evidence — kept.
    assert normalize_url("https://example.com:8080/") == "https://example.com:8080/"


def test_normalize_keeps_punycode_and_userinfo_evidence():
    # xn-- stays encoded: decoding it would hide the IDN attack.
    assert normalize_url("https://XN--80AK6AA92E.COM/x").startswith("https://xn--80ak6aa92e.com")
    # The '@' credential trick must survive normalization.
    normalized = normalize_url("http://user@example.com/path")
    assert "@" in normalized


def test_normalize_does_not_decode_or_collapse_path():
    # Encoded characters and double slashes are detection evidence.
    assert normalize_url("https://example.com/a%2Fb//c") == "https://example.com/a%2Fb//c"


def test_normalize_drops_fragment():
    assert normalize_url("https://example.com/app#/settings") == "https://example.com/app"


def test_normalize_bare_host_and_malformed():
    assert normalize_url("example.com/login") == "http://example.com/login"
    assert normalize_url("") is None
    assert normalize_url("   ") is None


def test_normalize_returns_nonweb_schemes_unchanged_for_caller_rejection():
    assert normalize_url("javascript:alert(1)") == "javascript:alert(1)"
    assert normalize_url("file:///etc/passwd") == "file:///etc/passwd"


def test_normalization_pair_is_evidence_ready():
    pair = normalization_pair("Example.COM/login#x")
    assert pair["url"] == "Example.COM/login#x"
    assert pair["normalized_url"] == "http://example.com/login"


# ---------------------------------------------------------------------------
# Decision policy (score separated from action)
# ---------------------------------------------------------------------------

def test_policy_safe_and_low_allow():
    assert get_url_decision("safe") == {"verdict": URL_VERDICT_SAFE, "action": URL_ACTION_ALLOW}
    assert get_url_decision("low")["action"] == URL_ACTION_ALLOW


def test_policy_medium_warns():
    assert get_url_decision("medium") == {"verdict": URL_VERDICT_SUSPICIOUS, "action": URL_ACTION_WARN}


def test_policy_high_warns_without_confidence_and_blocks_with_it():
    assert get_url_decision("high")["action"] == URL_ACTION_WARN
    assert get_url_decision("high", ml_confidence=0.89)["action"] == URL_ACTION_WARN
    assert get_url_decision("high", ml_confidence=0.95) == {
        "verdict": URL_VERDICT_MALICIOUS, "action": URL_ACTION_BLOCK,
    }


def test_policy_critical_always_blocks():
    assert get_url_decision("critical") == {"verdict": URL_VERDICT_MALICIOUS, "action": URL_ACTION_BLOCK}


def test_policy_unknown_severity_fails_visible_not_open():
    # Unknown/empty severity must NOT map to allow.
    decision = get_url_decision("")
    assert decision["action"] == URL_ACTION_WARN


# ---------------------------------------------------------------------------
# Rate limiting (per-user HTTP buckets)
# ---------------------------------------------------------------------------

def test_rate_limiter_allows_burst_then_denies():
    limiter = PerUserHTTPRateLimiter(rate_per_minute=60, burst=3)
    assert limiter.allow("user-a")
    assert limiter.allow("user-a")
    assert limiter.allow("user-a")
    assert not limiter.allow("user-a")


def test_rate_limiter_keys_are_per_user():
    limiter = PerUserHTTPRateLimiter(rate_per_minute=60, burst=1)
    assert limiter.allow("user-a")
    assert not limiter.allow("user-a")
    assert limiter.allow("user-b")


def test_rate_limiter_refills_over_time(monkeypatch):
    import time as time_mod

    limiter = PerUserHTTPRateLimiter(rate_per_minute=600, burst=1)  # 10 tokens/sec
    assert limiter.allow("user-a")
    assert not limiter.allow("user-a")
    real_monotonic = time_mod.monotonic
    monkeypatch.setattr(time_mod, "monotonic", lambda: real_monotonic() + 0.5)
    assert limiter.allow("user-a")  # 0.5s * 10 tokens/s = 5 tokens accrued


# ---------------------------------------------------------------------------
# SSRF defense-in-depth (cloud metadata hostnames never crawled)
# ---------------------------------------------------------------------------

def test_cloud_metadata_hostnames_classified_internal():
    from app.services.domain_intelligence import classify_host

    assert classify_host("metadata.google.internal") == "internal_local"
    assert classify_host("169.254.169.254") == "internal_local"
    assert classify_host("metadata.goog") == "internal_local"
    assert classify_host("example.com") == "public"
