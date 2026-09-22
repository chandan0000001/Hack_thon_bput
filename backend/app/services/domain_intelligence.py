"""Domain intelligence engine for Firecrawl-powered URL enrichment.

Pure-Python classification of hosts (internal vs public), brand-lookalike
detection (Levenshtein + homoglyph/leet normalization + brand embedding),
scrape-content confirmation, and redirect mismatch detection.

``live_enrich_url`` is the single async entry point wired into the URL
detection pipeline (routes_analysis + mail_scanner), AFTER the synchronous
``analyze_url_heuristics`` and BEFORE ``score_with_ml``. It is additive:
when enrichment is unavailable it returns the input indicator list unchanged,
and it never raises or touches the ML indicator path.
"""

from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from app.core.config import get_settings
from app.services import firecrawl_client
from app.services.firecrawl_client import FirecrawlScrape
from app.services.url_detector import BRAND_NAMES

logger = logging.getLogger("cyberguard.domain_intelligence")

# Suffixes that mark a host as internal/organizational (never crawled).
INTERNAL_LOCAL_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
    ".localdomain",
)

# Leet / homoglyph single-character normalizations.
_LEET_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
}

# Multi-character visual-confusion normalizations (checked before single chars).
_MULTI_GLYPH_MAP = {
    "rn": "m",
    "vv": "w",
}

_CREDENTIAL_FORM_RE = re.compile(r"<input[^>]+type=[\"']password[\"']", re.IGNORECASE)

# Word-boundary brand match used for content confirmation.
def _brand_word_re(brand: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(brand)}\b", re.IGNORECASE)


# --- Simple curated stand-in for a top-1M domain list (no new dependency) ---
_MAJOR_DOMAINS = frozenset(
    {
        "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com",
        "microsoft.com", "office.com", "office365.com", "outlook.com", "live.com",
        "netflix.com", "paypal.com", "dhl.com", "fedex.com", "hsbc.com",
        "wikipedia.org", "twitter.com", "x.com", "linkedin.com", "instagram.com",
        "github.com", "cloudflare.com", "yahoo.com", "bing.com", "adobe.com",
        "dropbox.com", "zoom.us", "steampowered.com", "ebay.com", "chase.com",
        "wellsfargo.com", "bankofamerica.com", "coinbase.com", "binance.com",
    }
)


def _registrable_domain(host: str) -> str:
    """Approximate registrable domain: last two labels of a lowercased host.

    Good-enough heuristic (no public-suffix dependency); multi-part public
    suffixes like ``co.uk`` collapse to ``co.uk``-level names, which only makes
    lookalike checks slightly more conservative.
    """
    labels = [label for label in host.lower().split(".") if label]
    if len(labels) < 2:
        return host.lower()
    return ".".join(labels[-2:])


def classify_host(host: str) -> str:
    """Classify a host as ``internal_local`` or ``public``.

    internal_local covers loopback / RFC1918 / link-local IP literals, the
    documented internal suffixes, single-label hostnames, and ``localhost``.
    """
    normalized = (host or "").strip().lower().rstrip(".")
    if not normalized:
        return "public"
    if normalized == "localhost":
        return "internal_local"

    # IP-literal classification (IPv4 dotted-quad + bracketed IPv6).
    candidate = normalized
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if ":" in candidate:
        try:
            import ipaddress

            address = ipaddress.ip_address(candidate)
            if address.is_loopback or address.is_link_local or address.is_private:
                return "internal_local"
        except ValueError:
            pass
    elif candidate.count(".") == 3 and all(part.isdigit() for part in candidate.split(".")):
        try:
            import ipaddress

            address = ipaddress.ip_address(candidate)
            if (
                address.is_loopback
                or address.is_link_local
                or address.is_private
                or address.is_reserved
            ):
                return "internal_local"
        except ValueError:
            pass

    if normalized.endswith(INTERNAL_LOCAL_SUFFIXES):
        return "internal_local"
    if "." not in normalized:
        return "internal_local"  # single-label hostname (e.g. "printer", "nas")
    return "public"


def _normalize_label(label: str) -> str:
    """Apply multi-glyph then single-character homoglyph/leet normalization."""
    lowered = label.lower()
    for source, target in _MULTI_GLYPH_MAP.items():
        lowered = lowered.replace(source, target)
    return "".join(_LEET_MAP.get(char, char) for char in lowered)


def _levenshtein(a: str, b: str, max_distance: int = 2) -> int:
    """Pure-Python Levenshtein DP (no external dependency)."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            substitute_cost = previous[j - 1] + (char_a != char_b)
            current.append(min(insert_cost, delete_cost, substitute_cost))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def lookalike_candidate(host: str) -> tuple[Optional[str], str]:
    """Compare a host's registrable domain against known brands.

    Returns ``(brand, reason)`` where ``brand`` is ``None`` when the host is
    not a lookalike candidate. ``reason`` is one of:
    ``homoglyph_levenshtein`` (distance <= 2 after normalization),
    ``exact_brand_tld`` (brand SLD on an unusual pairing), or
    ``brand_embedded`` (brand padded with extra hyphens/words).
    """
    host = (host or "").strip().lower().rstrip(".")
    registrable = _registrable_domain(host)
    if not registrable or "." not in registrable:
        return None, ""
    sld, tld = registrable.rsplit(".", 1)

    for brand in BRAND_NAMES:
        if sld == brand and tld in {"com", "net", "org"}:
            # Genuine brand domain (e.g. paypal.com) — never a candidate.
            return None, ""
        if sld == brand:
            return brand, f"exact brand SLD '{brand}' on non-canonical TLD '.{tld}'"

    for brand in BRAND_NAMES:
        normalized = _normalize_label(sld)
        normalized_brand = _normalize_label(brand)
        if normalized == normalized_brand:
            return brand, "homoglyph/leet normalization matches brand exactly"
        if brand in normalized and normalized != normalized_brand:
            return brand, "brand embedded in host label with extra words/hyphens"
        distance = _levenshtein(normalized, normalized_brand)
        if distance <= 2:
            return brand, (
                f"label '{sld}' is within Levenshtein distance {distance} of "
                f"brand '{brand}' after homoglyph normalization"
            )
    return None, ""


def confirm_with_content(scrape: FirecrawlScrape, brand: str) -> tuple[bool, str]:
    """Confirm a lookalike candidate using scraped page content.

    Confirmation signals (any one suffices):
      * word-boundary brand mention in metadata.title or markdown;
      * credential (password) form in the HTML;
      * copyright / logo text referencing the brand.
    Returns ``(confirmed, evidence)`` — evidence strings never include raw HTML.
    """
    brand_re = _brand_word_re(brand)

    title_hit = brand_re.search(scrape.title or "")
    if title_hit:
        return True, f"brand '{brand}' appears in page title"
    markdown_hit = brand_re.search(scrape.markdown or "")
    if markdown_hit:
        return True, f"brand '{brand}' appears in page body text"

    if _CREDENTIAL_FORM_RE.search(scrape.html or ""):
        return True, "credential (password) form present in page HTML"

    copyright_re = re.compile(rf"(?:©|copyright|all rights reserved).{{0,80}}", re.IGNORECASE)
    match = copyright_re.search(scrape.markdown or "")
    if match and brand_re.search(match.group(0)):
        return True, f"copyright text references brand '{brand}'"
    return False, ""


def has_credential_form(scrape: FirecrawlScrape) -> bool:
    """True when the scraped HTML contains a password input field."""
    return bool(_CREDENTIAL_FORM_RE.search(scrape.html or ""))


def redirect_mismatch(url: str, scrape: FirecrawlScrape) -> bool:
    """True when the scrape's final/source registrable domain differs from the
    submitted URL's registrable domain (redirect-chain domain switch)."""
    submitted = _registrable_domain(urlparse(url).hostname or "")
    if not submitted:
        return False
    final_host = ""
    if scrape.source_url:
        final_host = urlparse(scrape.source_url).hostname or ""
    if not final_host and scrape.status_code and scrape.links:
        # Fall back to the first self-referential link when metadata is absent.
        for link in scrape.links:
            link_host = urlparse(link).hostname or ""
            if link_host:
                final_host = link_host
                break
    if not final_host:
        return False
    return _registrable_domain(final_host) != submitted


def _is_likely_top_1m(host: str) -> bool:
    """Curated major-domain check standing in for a top-1M list.

    Credential forms on these domains are expected (login pages) and must not
    raise ``live_credential_form``. See FIRECRAWL_INTEGRATION.md for the
    documented limitation of this dependency-free approximation.
    """
    return _registrable_domain(host) in _MAJOR_DOMAINS


def _indicator(indicator_type: str, severity: str, value: str, description: str) -> dict:
    return {
        "type": indicator_type,
        "value": value,
        "severity": severity,
        "description": description,
    }


async def live_enrich_url(url: str, indicators: list[dict]) -> list[dict]:
    """Additive Firecrawl enrichment for the URL detection pipeline.

    Contract:
      * only ``http``/``https`` URLs proceed; anything else is returned as-is;
      * ``internal_local`` hosts gain a ``local_internal_domain`` indicator and
        are NEVER crawled (privacy guard: internal URLs must not leave the
        platform) — subject to ``FIRECRAWL_SKIP_INTERNAL_URLS``;
      * public hosts are scraped only when enabled + API key present;
      * a ``None`` scrape (disabled / timeout / failure) returns the input
        indicators unchanged (byte-identical degradation);
      * this function never raises.
    """
    try:
        return await _live_enrich_url_inner(url, indicators)
    except Exception as exc:  # enrichment failures must never fail a scan
        logger.warning("Live URL enrichment failed; returning indicators unchanged: %s", exc)
        return indicators


async def _live_enrich_url_inner(url: str, indicators: list[dict]) -> list[dict]:
    """Internal enrichment body (see :func:`live_enrich_url` for the contract)."""
    settings = get_settings()
    try:
        parsed = urlparse(url)
    except ValueError:
        return indicators
    if parsed.scheme not in ("http", "https"):
        return indicators
    host = (parsed.hostname or "").lower()
    if not host:
        return indicators

    if classify_host(host) == "internal_local":
        if settings.FIRECRAWL_SKIP_INTERNAL_URLS:
            logger.info("Internal/local host '%s' flagged without crawling (privacy guard).", host)
            indicators.append(
                _indicator(
                    "local_internal_domain",
                    "medium",
                    host,
                    "The URL points to an internal/local network host; it was "
                    "classified but NOT crawled (internal URLs never leave the platform).",
                )
            )
        return indicators

    scrape = await firecrawl_client.scrape_url(url)
    if scrape is None:
        return indicators  # disabled / timeout / failure: unchanged degradation

    brand, reason = lookalike_candidate(host)
    if brand is not None:
        confirmed, evidence = confirm_with_content(scrape, brand)
        if confirmed:
            indicators.append(
                _indicator(
                    "lookalike_domain_confirmed",
                    "critical",
                    host,
                    f"Lookalike domain impersonating '{brand}' CONFIRMED by live page "
                    f"content ({reason}; {evidence}).",
                )
            )
        else:
            indicators.append(
                _indicator(
                    "lookalike_domain_candidate",
                    "medium",
                    host,
                    f"Host looks like a '{brand}' lookalike ({reason}); live content "
                    "did not confirm impersonation.",
                )
            )

    if has_credential_form(scrape) and not _is_likely_top_1m(host):
        indicators.append(
            _indicator(
                "live_credential_form",
                "high",
                host,
                "Live page contains a password input on a non-major domain — "
                "consistent with credential harvesting.",
            )
        )

    if redirect_mismatch(url, scrape):
        final_host = urlparse(scrape.source_url).hostname if scrape.source_url else "unknown"
        indicators.append(
            _indicator(
                "redirect_domain_mismatch",
                "medium",
                f"{host} -> {final_host}",
                "The redirect chain switched registrable domains between the "
                "submitted URL and the final landing page.",
            )
        )

    return indicators
