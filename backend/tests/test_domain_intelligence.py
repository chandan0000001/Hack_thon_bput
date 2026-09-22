"""Tests for the domain intelligence engine (Requirement E).

Covers: lookalike candidates (paypa1.com, paypaI.com vs paypal.com), homoglyph
normalization, internal host classification (192.168.1.10, printer.local,
intranet), redirect mismatch, credential-form confirmation, and the no-key
graceful path asserting indicators are returned unmodified.
"""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.services import firecrawl_client, domain_intelligence
from app.services.domain_intelligence import (
    classify_host,
    confirm_with_content,
    has_credential_form,
    live_enrich_url,
    lookalike_candidate,
    redirect_mismatch,
)
from app.services.firecrawl_client import FirecrawlScrape


# ---------------------------------------------------------------------------
# classify_host
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "host",
    [
        "192.168.1.10",
        "10.0.0.5",
        "172.16.3.4",
        "127.0.0.1",
        "169.254.1.1",
        "printer.local",
        "nas.internal",
        "intranet.corp",
        "router.lan",
        "myhome.home",
        "hr.intranet",
        "db.localdomain",
        "localhost",
        "printer",  # single-label hostname
    ],
)
def test_classify_host_internal_local(host: str):
    assert classify_host(host) == "internal_local"


@pytest.mark.parametrize(
    "host",
    ["paypal.com", "example.co.uk", "8.8.8.8", "paypa1.com", "www.google.com"],
)
def test_classify_host_public(host: str):
    assert classify_host(host) == "public"


# ---------------------------------------------------------------------------
# lookalike_candidate
# ---------------------------------------------------------------------------

def test_paypa1_is_paypal_lookalike():
    brand, reason = lookalike_candidate("paypa1.com")
    assert brand == "paypal"
    assert "homoglyph" in reason or "Levenshtein" in reason


def test_paypaI_capital_i_is_paypal_lookalike():
    brand, reason = lookalike_candidate("paypaI.com")
    assert brand == "paypal"


def test_g00gle_homoglyph():
    brand, _ = lookalike_candidate("g00gle.com")
    assert brand == "google"


def test_rn_to_m_normalization():
    brand, _ = lookalike_candidate("payrn1l.com")  # payrn1l -> paymil -> paypal (2 edits)
    assert brand == "paypal"


def test_brand_embedded_with_hyphens():
    brand, reason = lookalike_candidate("paypal-secure-login.com")
    assert brand == "paypal"
    assert "embedded" in reason


def test_brand_on_unusual_tld():
    brand, _ = lookalike_candidate("paypal.xyz")
    assert brand == "paypal"


def test_genuine_brand_domain_not_flagged():
    for host in ("paypal.com", "google.com", "www.paypal.com", "mail.google.com"):
        brand, _ = lookalike_candidate(host)
        assert brand is None, host


def test_unrelated_domain_not_flagged():
    brand, _ = lookalike_candidate("example-shop.com")
    assert brand is None


# ---------------------------------------------------------------------------
# confirm_with_content / has_credential_form / redirect_mismatch
# ---------------------------------------------------------------------------

def _scrape(**kwargs) -> FirecrawlScrape:
    return FirecrawlScrape(**kwargs)


def test_confirm_via_title():
    scrape = _scrape(title="PayPal Login - Security Check", markdown="nothing here")
    confirmed, evidence = confirm_with_content(scrape, "paypal")
    assert confirmed and "title" in evidence


def test_confirm_via_markdown_word_boundary():
    scrape = _scrape(markdown="Sign in to your paypal account below.")
    confirmed, _ = confirm_with_content(scrape, "paypal")
    assert confirmed


def test_word_boundary_does_not_match_substring():
    scrape = _scrape(markdown="We recommend paypalsoftwaretools for developers.")
    confirmed, _ = confirm_with_content(scrape, "paypal")
    assert not confirmed


def test_confirm_via_credential_form():
    scrape = _scrape(
        html="<form><input name='email'><input type='password' name='pw'></form>"
    )
    confirmed, evidence = confirm_with_content(scrape, "paypal")
    assert confirmed and "credential" in evidence


def test_no_confirmation_without_signals():
    scrape = _scrape(markdown="A totally boring page.", html="<p>hello</p>")
    confirmed, _ = confirm_with_content(scrape, "paypal")
    assert not confirmed


def test_has_credential_form_variants():
    assert has_credential_form(_scrape(html="<input type=\"password\">"))
    assert has_credential_form(_scrape(html="<INPUT TYPE='PASSWORD' NAME='pw'>"))
    assert not has_credential_form(_scrape(html="<input type='text'>"))


def test_redirect_mismatch_detected():
    submitted = "https://paypal-verify.com/login"
    scrape = _scrape(source_url="https://evil-redirect.example/", status_code=200)
    assert redirect_mismatch(submitted, scrape) is True


def test_redirect_mismatch_same_domain_not_flagged():
    submitted = "https://paypal-verify.com/login"
    scrape = _scrape(source_url="https://www.paypal-verify.com/ok", status_code=200)
    assert redirect_mismatch(submitted, scrape) is False


def test_redirect_mismatch_without_metadata_is_false():
    assert redirect_mismatch("https://example.com/", _scrape()) is False


# ---------------------------------------------------------------------------
# live_enrich_url — pipeline integration
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(firecrawl_client, "_redis_client", None)
    yield
    firecrawl_client._redis_client = None


@pytest.mark.asyncio
async def test_internal_host_flagged_and_never_crawled(monkeypatch: pytest.MonkeyPatch):
    async def fail_scrape(url: str):
        raise AssertionError("internal hosts must never be crawled")

    monkeypatch.setattr(firecrawl_client, "scrape_url", fail_scrape)
    indicators = [{"type": "url_length", "value": "10", "severity": "medium", "description": "x"}]
    result = await live_enrich_url("http://192.168.1.10/admin", indicators)
    types = [i["type"] for i in result]
    assert "local_internal_domain" in types
    assert result[0] is indicators[0]  # original indicators preserved


@pytest.mark.asyncio
async def test_no_key_returns_indicators_unmodified(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "", raising=False)
    monkeypatch.setattr(settings, "FIRECRAWL_ENABLED", True, raising=False)

    async def fail_scrape(url: str):
        raise AssertionError("no scrape allowed without an API key")

    monkeypatch.setattr(firecrawl_client, "scrape_url", fail_scrape)
    original = [{"type": "ip_host", "value": "1.2.3.4", "severity": "critical", "description": "d"}]
    result = await live_enrich_url("https://example.com/", list(original))
    assert result == original  # byte-identical degradation


@pytest.mark.asyncio
async def test_none_scrape_returns_indicators_unchanged(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "fc-test1234", raising=False)

    async def none_scrape(url: str):
        return None  # simulated timeout/failure

    monkeypatch.setattr(firecrawl_client, "scrape_url", none_scrape)
    original = [{"type": "url_entropy", "value": "4.5", "severity": "medium", "description": "d"}]
    assert await live_enrich_url("https://example.com/", list(original)) == original


@pytest.mark.asyncio
async def test_non_http_scheme_skips_enrichment(monkeypatch: pytest.MonkeyPatch):
    async def fail_scrape(url: str):
        raise AssertionError("only http/https proceed")

    monkeypatch.setattr(firecrawl_client, "scrape_url", fail_scrape)
    original: list[dict] = []
    assert await live_enrich_url("ftp://example.com/file", list(original)) == original


@pytest.mark.asyncio
async def test_confirmed_lookalike_appends_critical_indicator(
    monkeypatch: pytest.MonkeyPatch,
):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "fc-test1234", raising=False)

    async def scrape(url: str):
        return FirecrawlScrape(
            title="PayPal Security Center",
            markdown="Log in to your paypal account.",
            html="<input type='password'>",
            source_url="https://paypa1.com/login",
        )

    monkeypatch.setattr(firecrawl_client, "scrape_url", scrape)
    result = await live_enrich_url("https://paypa1.com/login", [])
    types = {i["type"]: i for i in result}
    assert types["lookalike_domain_confirmed"]["severity"] == "critical"
    assert types["live_credential_form"]["severity"] == "high"


@pytest.mark.asyncio
async def test_unconfirmed_lookalike_is_medium_candidate(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "fc-test1234", raising=False)

    async def scrape(url: str):
        return FirecrawlScrape(markdown="Nothing relevant here.", html="<p>hi</p>")

    monkeypatch.setattr(firecrawl_client, "scrape_url", scrape)
    result = await live_enrich_url("https://paypa1.com/", [])
    candidate = [i for i in result if i["type"] == "lookalike_domain_candidate"]
    assert len(candidate) == 1 and candidate[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_credential_form_skipped_on_major_domain(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "fc-test1234", raising=False)

    async def scrape(url: str):
        return FirecrawlScrape(html="<input type='password'>")  # legit Google login

    monkeypatch.setattr(firecrawl_client, "scrape_url", scrape)
    result = await live_enrich_url("https://accounts.google.com/signin", [])
    assert all(i["type"] != "live_credential_form" for i in result)


@pytest.mark.asyncio
async def test_redirect_mismatch_indicator_appended(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "fc-test1234", raising=False)

    async def scrape(url: str):
        return FirecrawlScrape(source_url="https://evil.example/landing")

    monkeypatch.setattr(firecrawl_client, "scrape_url", scrape)
    result = await live_enrich_url("https://paypa1-secure.com/", [])
    mismatch = [i for i in result if i["type"] == "redirect_domain_mismatch"]
    assert len(mismatch) == 1 and mismatch[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_enrichment_never_raises(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "FIRECRAWL_API_KEY", "fc-test1234", raising=False)

    async def boom(url: str):
        raise RuntimeError("unexpected provider explosion")

    monkeypatch.setattr(firecrawl_client, "scrape_url", boom)
    original = [{"type": "x", "value": "y", "severity": "low", "description": "z"}]
    result = await live_enrich_url("https://example.com/", list(original))
    assert result == original


def test_levenshtein_reference():
    assert domain_intelligence._levenshtein("paypal", "paypal") == 0
    assert domain_intelligence._levenshtein("paypa1", "paypal") == 1
    assert domain_intelligence._levenshtein("kitten", "sitting") == 3
