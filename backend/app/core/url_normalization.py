"""Shared URL normalization for the URL analysis engine (both entry points).

The dashboard and the browser extension POST the same URL text to
POST /analysis/url; both must be analyzed against ONE canonical form so
verdicts, caches and SOC events agree. Rules are deliberately conservative —
normalization must never erase detection evidence:

  * scheme      — http/https only are analyzed (lowercased); anything else
                  passes through unchanged for the caller to reject
  * hostname    — lowercased, trailing dot stripped, kept in PUNYCODE form
                  (xn-- is itself detection evidence — decoding it would hide
                  an IDN attack from lexical features)
  * port        — default ports (80/443) dropped; other ports kept (evidence)
  * userinfo    — kept (the '@' credential trick is an indicator, not noise)
  * path        — kept verbatim (no slash collapsing, no percent-decoding:
                  encoded characters are evidence)
  * query       — kept verbatim (no reordering)
  * fragment    — dropped (never sent to servers; SPA fragments would split
                  cache keys for the same resource)
  * malformed   — retried once with an http:// prefix (bare-host input like
                  "example.com/login"); unparseable input returns None

Returns both forms so callers can store raw + normalized as evidence.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse
import re

DEFAULT_PORTS = {"http": 80, "https": 443}
ANALYZABLE_SCHEMES = ("http", "https")

# URL-spec scheme shape: letter followed by letters/digits/+/-/. and then ':'
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def normalize_url(raw_url: str) -> str | None:
    """Canonical analysis form of a URL; None when unparseable."""
    raw = str(raw_url or "").strip()
    if not raw:
        return None

    # Prefix bare hosts (example.com/login) — but NOT scheme-like input
    # (javascript:, file:, data: have no '.' before ':' and must not become
    # http URLs). Host:port inputs (example.com:8080/x) keep the http prefix
    # because the text before ':' contains a dot.
    scheme_match = _SCHEME_RE.match(raw)
    if "://" in raw:
        candidate = raw
    elif scheme_match and "." not in scheme_match.group(0)[:-1]:
        candidate = raw
    else:
        candidate = f"http://{raw}"

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme not in ANALYZABLE_SCHEMES:
        # Non-web schemes (file:, javascript:, chrome:, ...) are not analyzed;
        # return the input so callers can reject with their own message.
        return raw

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None

    # Rebuild the netloc: lowercased host (trailing dot stripped), userinfo
    # kept verbatim (the '@' credential trick is evidence), non-default ports
    # kept, default ports dropped. IPv6 hosts re-bracket.
    raw_netloc = parsed.netloc
    userinfo, at, _ = raw_netloc.rpartition("@")
    prefix = userinfo + at if at else ""
    port = parsed.port
    host_for_netloc = f"[{host}]" if ":" in host else host
    netloc = prefix + host_for_netloc
    if port is not None and DEFAULT_PORTS.get(parsed.scheme) != port:
        netloc += f":{port}"

    return urlunparse((parsed.scheme, netloc, parsed.path or "", parsed.params, parsed.query, ""))


def normalization_pair(raw_url: str) -> dict[str, str | None]:
    """Evidence pair for storage: {'url': raw, 'normalized_url': normalized}."""
    return {"url": str(raw_url or ""), "normalized_url": normalize_url(raw_url)}
