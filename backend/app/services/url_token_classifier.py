"""Format-based URL token classification and domain-context analysis (URL-FP-FIX-V2).

Scans URL path and query parameters for known cryptographic/identifier structures
(JWT, UUID, Base64/Base64URL, Long Hex) without checking specific path or parameter
names, and verifies domain hygiene (no IP address, homoglyphs, or typosquatting).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

# Mathematical structure regexes — ZERO hardcoded path or parameter names
JWT_PATTERN = re.compile(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$")
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{16,}$")
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")

COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "xyz",
    "top", "info", "biz", "online", "site", "app", "dev", "cloud", "store",
    "tech", "club", "vip", "pro", "mobi", "asia", "me", "cc", "tv", "us",
    "uk", "de", "fr", "ru", "cn", "in", "jp", "au", "ca", "br", "it", "nl",
}

SUSPICIOUS_TLDS_EXTENDED = {
    "xyz", "top", "zip", "click", "link", "work", "loan", "cam", "rest",
    "tk", "ml", "ga", "cf", "gq", "surf", "buzz", "sbs", "monster", "site",
}

FREE_HOSTING_PLATFORMS = {
    "vercel.app", "workers.dev", "pages.dev", "firebaseapp.com",
    "glitch.me", "netlify.app", "web.app", "github.io",
}


def is_jwt_token(value: str) -> bool:
    """Detect JWT structure: 3 Base64URL segments separated by dots."""
    if not value or len(value) < 15:
        return False
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return bool(JWT_PATTERN.match(value)) and all(len(p) >= 2 for p in parts)


def is_uuid_token(value: str) -> bool:
    """Detect standard 8-4-4-4-12 UUID format."""
    if not value or len(value) != 36:
        return False
    return bool(UUID_PATTERN.match(value))


def is_hex_token(value: str) -> bool:
    """Detect continuous hexadecimal token (>= 16 characters)."""
    if not value or len(value) < 16:
        return False
    return bool(HEX_PATTERN.match(value))


def is_base64_token(value: str) -> bool:
    """Detect Base64/Base64URL tokens (>= 16 characters with +, /, =, -, _ or mixed alphanumeric)."""
    if not value or len(value) < 16:
        return False
    if not BASE64_PATTERN.match(value):
        return False
    # Explicit Base64 / Base64URL characters (+, /, =, -, _) or mixed-case alphanumeric signature
    has_symbols = any(c in value for c in "+/=_-")
    has_digits = any(c.isdigit() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    return has_symbols or (has_digits and (has_upper or has_lower))


def classify_token_format(value: str) -> str | None:
    """Classify mathematical token format without checking parameter/path names."""
    candidate = value.strip()
    if is_uuid_token(candidate):
        return "uuid"
    if is_jwt_token(candidate):
        return "jwt"
    if is_hex_token(candidate):
        return "hex"
    if is_base64_token(candidate):
        return "base64"
    return None


def is_domain_clean(host_or_url: str) -> bool:
    """Evaluate whether the domain passes existing typosquatting, homoglyph, and IP checks."""
    if not host_or_url:
        return False
    if "://" in host_or_url:
        host = urlparse(host_or_url).hostname or ""
    elif "/" in host_or_url:
        host = urlparse(f"http://{host_or_url}").hostname or ""
    else:
        host = host_or_url

    host = host.strip().lower().rstrip(".")
    if not host:
        return False

    # 1. IP address check
    labels = host.split(".")
    if len(labels) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in labels):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass

    # 2. Homoglyph / IDN / Punycode check
    if "xn--" in host or any(not c.isascii() for c in host):
        return False
    try:
        from ml.url_features_v3 import homoglyph_skeleton
        if homoglyph_skeleton(host) != host:
            return False
    except Exception:
        pass

    # 3. Domain randomness / high entropy
    try:
        from ml.url_features_v3 import _registrable, shannon_entropy_v3
        reg = _registrable(host)
        sld = reg.split(".")[0] if "." in reg else reg
        if shannon_entropy_v3(sld) > 3.4 and len(sld) > 10:
            return False
        digits = sum(c.isdigit() for c in host)
        alnum = sum(c.isalnum() for c in host)
        if digits >= 5 and alnum and (digits / alnum) > 0.25:
            return False

        # Free hosting platforms with high-entropy / long subdomains
        if reg in FREE_HOSTING_PLATFORMS:
            sub = host[:-len(reg)].rstrip(".")
            if len(sub) > 8 or shannon_entropy_v3(sub) > 3.0:
                return False
    except Exception:
        pass

    # 4. Typosquatting / Brand Lookalike check
    try:
        from app.services.domain_intelligence import lookalike_candidate
        brand, _ = lookalike_candidate(host)
        if brand is not None:
            return False
    except Exception:
        pass

    try:
        from ml.url_features_v3 import BRAND_OFFICIAL_DOMAINS_V4, _brand_signals, _registrable
        reg = _registrable(host)
        host_labels = [p for p in host.split(".") if p]
        bs = _brand_signals(host, reg, host_labels)
        if bs.get("brand_typo_min_distance", 8) <= 2 and reg not in BRAND_OFFICIAL_DOMAINS_V4.values():
            return False
        if bs.get("brand_typo_exact_leet", 0) == 1:
            return False
        if bs.get("brand_in_nonofficial_domain", 0) == 1:
            return False
    except Exception:
        pass

    # 5. Brand in subdomain check
    try:
        from app.services.url_detector import BRAND_NAMES
        host_labels = [p for p in host.split(".") if p]
        if len(host_labels) >= 3:
            registrable = ".".join(host_labels[-2:])
            subdomain_part = ".".join(host_labels[:-2])
            for brand in BRAND_NAMES:
                if brand in subdomain_part and brand not in registrable:
                    return False
    except Exception:
        pass

    # 6. Subdomain spoofing check (e.g. clean-domain.com.evil.net)
    host_labels = [p for p in host.split(".") if p]
    if len(host_labels) >= 3:
        subdomain_labels = host_labels[:-2]
        if any(label in COMMON_TLDS for label in subdomain_labels):
            return False

    # 7. Suspicious TLD check
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    try:
        from app.services.url_detector import SUSPICIOUS_TLDS
        if tld in SUSPICIOUS_TLDS:
            return False
    except Exception:
        pass
    if tld in SUSPICIOUS_TLDS_EXTENDED:
        return False

    return True


def analyze_url_structure(url: str) -> dict[str, Any]:
    """Scan URL path and query parameters for mathematical token structures and evaluate domain cleanliness.

    Returns:
      has_structured_token: bool (True if path/query contains JWT, UUID, Base64, or long hex)
      token_locations: list[str] (e.g. ['query.param_x', 'path.segment_2'])
      domain_is_clean: bool (True if domain passes typosquatting, homoglyph, and IP checks)
    """
    raw = str(url or "").strip()
    if not raw:
        return {
            "has_structured_token": False,
            "token_locations": [],
            "domain_is_clean": False,
        }

    try:
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    except ValueError:
        return {
            "has_structured_token": False,
            "token_locations": [],
            "domain_is_clean": False,
        }

    token_locations: list[str] = []

    # 1. Scan path segments (1-indexed, e.g. path.segment_2)
    path_segments = [seg for seg in (parsed.path or "").split("/") if seg]
    for idx, seg in enumerate(path_segments, 1):
        fmt = classify_token_format(seg)
        if fmt:
            token_locations.append(f"path.segment_{idx}")

    # 2. Scan query parameters (e.g. query.param_x or query.a)
    try:
        query_params = parse_qsl(parsed.query or "", keep_blank_values=True)
    except Exception:
        query_params = []

    for key, val in query_params:
        target = val if val else key
        fmt = classify_token_format(target)
        if fmt:
            token_locations.append(f"query.{key}")

    clean = is_domain_clean(parsed.hostname or "")

    return {
        "has_structured_token": bool(token_locations),
        "token_locations": token_locations,
        "domain_is_clean": clean,
    }
