"""URL v3 feature extraction — domain reputation separated from URL structure.

Root cause this version fixes: the v2 model over-indexed on total URL length
and total entropy, so a benign domain with a long marketing query string
(medium.com/?source=email-...&utm_medium=email) scored like a lookalike
phishing host (paypa1-secure.tk/login). v3 gives the model the evidence it
needs to separate the two cases:

  1. DOMAIN REPUTATION  — is_top_1m: registrable domain in the Umbrella top-1M
     whitelist (same set the runtime uses, loaded once into an in-memory set
     for O(1) lookups).
  2. STRUCTURAL ENTROPY — entropy computed separately for the domain, the
     path and the query, so a high-entropy tracking blob on a reputable host
     no longer contaminates the host signal.
  3. LENGTH METRICS     — domain_length / path_length / query_length split
     out of total_length.
  4. TRACKING PARAMS    — has_tracking_params / num_query_params: benign
     marketing-email signals.
  5. MALICIOUS INDICATORS — IP host, dot/subdomain count, '@' trick,
     suspicious free TLDs, domain digit-ratio and hyphen count (leet lookalikes),
     credential-path keywords.

v4 EXTENSION (cascaded-pipeline Phase 1) — IDN/homoglyph + brand typo-squatting:
the 19 legacy columns above are FROZEN: the deployed url_xgb_v3(.1) model
consumes exactly this vector via vectorize_v3 / app/services/ml_inference.py,
so legacy values must stay bit-identical. The v4 schema (FEATURE_COLUMNS_V4)
appends new columns consumed only by the next training run:

  6. IDN / PUNYCODE    — non-ASCII host, xn-- labels (and how many), and
     mixed-script detection after decoding (e.g. Cyrillic + Latin).
  7. HOMOGLYPH         — confusable fold (Cyrillic а→a, Greek ο→o, ...):
     flags hosts whose skeleton differs from their literal form.
  8. BRAND TYPO-SQUATTING — capped Damerau-Levenshtein distance from the
     leet-normalized SLD to the nearest known brand stem, an exact-leet-match
     flag (paypa1 → paypal), and a brand-in-non-official-domain flag
     (paypal in a subdomain/sld while the registrable domain is not the
     brand's official domain).
  9. RANK PROXY        — log10 rank from the ordered top-1M file (Tranco-rank
     stand-in; swap in a real Tranco ranks file when available without
     changing the schema).
 10. EXTENDED TLDs     — suspicious-TLD list widened beyond the frozen legacy
     set (zip, mov, cam, link, ...).

MUST stay in sync between training (ml/scripts/train_url_v3.py) and inference
(app/services/ml_inference.py) — both go through this module, so editing here
keeps them identical.
"""

import math
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

# Fixed column order for the XGBoost feature matrix (flat dict -> vector).
FEATURE_COLUMNS_V3 = [
    "is_top_1m",
    "domain_entropy",
    "path_entropy",
    "query_entropy",
    "domain_length",
    "path_length",
    "query_length",
    "total_length",
    "has_tracking_params",
    "num_query_params",
    "has_ip",
    "num_dots",
    "num_subdomains",
    "has_at_symbol",
    "suspicious_tld",
    "http_only",
    "domain_digit_ratio",
    "domain_hyphens",
    "has_suspicious_path_keyword",
]

SUSPICIOUS_TLDS_V3 = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "loan", "click", "rest"}

TRACKING_PARAM_PATTERN = re.compile(r"(?:^|[?&])(utm_[a-z_]+=|source=|ref=|ref_src=|campaign=|email=|fbclid=|gclid=|mc_cid=|mc_eid=|_hsenc=|mkt_tok=)", re.IGNORECASE)

CREDENTIAL_PATH_PATTERN = re.compile(
    r"(?:login|signin|sign-in|verify|secure|account|update|billing|password|confirm|webscr|wallet)",
    re.IGNORECASE,
)

IP_HOST_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# ---------------------------------------------------------------------------
# v4 extension constants (legacy constants above are frozen — do not touch)
# ---------------------------------------------------------------------------

# Column order of the v4 feature matrix = the 19 frozen legacy columns first
# (so a v4 vector starts with the exact schema the v3.1 model was trained on),
# then the new columns below.
NEW_FEATURE_COLUMNS_V4 = [
    "is_idn",
    "is_punycode",
    "punycode_label_count",
    "mixed_script_domain",
    "homoglyph_confusable",
    "brand_typo_min_distance",
    "brand_typo_exact_leet",
    "brand_in_nonofficial_domain",
    "domain_rank_log",
    "suspicious_tld_extended",
]

FEATURE_COLUMNS_V4 = FEATURE_COLUMNS_V3 + NEW_FEATURE_COLUMNS_V4

# Default rank assigned when the domain is absent from (or the file lacks) the
# ordered top-1M list: log10(10^7) = unknown / beyond rank 1M.
UNKNOWN_RANK_LOG = 7.0

# Widened suspicious-TLD set for the v4 column only. The legacy
# SUSPICIOUS_TLDS_V3 set above stays frozen so the deployed model's inputs do
# not shift before retraining.
EXPANDED_SUSPICIOUS_TLDS_V4 = SUSPICIOUS_TLDS_V3 | {
    "zip", "mov", "cam", "click", "link", "sbs", "quest", "zone", "buzz",
    "surf", "monster", "cfd", "icu", "cyou", "casa", "lol", "bar", "kim",
    "country", "download", "stream", "fit", "review", "gdn", "wang",
}

PUNYCODE_LABEL_PREFIX = "xn--"

# Leet-speak fold applied before brand distance (paypa1 -> paypal, 5ecurity ->
# security). Hyphens are stripped separately so "paypal-secure" folds to
# "paypalsecure" for the prefix/subdomain checks.
LEET_TRANSLATION = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i", "|": "l",
})

# Confusable fold: the homoglyph 'skeleton' reduction for the characters that
# actually occur in IDN phishing (Cyrillic/Greek/Armenian lookalikes of ASCII).
# Deliberately a plain dict — no external dependency — and deliberately not
# exhaustive: it only needs to fold the confusables that change a host's
# apparent spelling (а->a, о->o, ...). Chars absent from the map pass through.
HOMOGLYPH_CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "ԛ": "q",
    "ѡ": "w", "ҥ": "h", "ќ": "k", "м": "m", "т": "t", "в": "b",
    "н": "h", "к": "k", "ю": "io",
    # Greek
    "ο": "o", "α": "a", "ν": "v", "ε": "e", "ρ": "p", "τ": "t", "υ": "u",
    "ι": "i", "κ": "k", "χ": "x", "ϲ": "c", "ϳ": "j",
    # Armenian + misc
    "հ": "h", "օ": "o", "ո": "n", "ց": "g", "ⅼ": "l", "１": "1",
}

# Unicode codepoint ranges for the scripts that matter in mixed-script IDN
# attacks. ASCII Latin is handled separately; Latin-1/Latin Extended share the
# "latin" bucket with it.
_SCRIPT_RANGES = (
    ("cyrillic", 0x0400, 0x04FF),
    ("cyrillic_supplement", 0x0500, 0x052F),
    ("greek", 0x0370, 0x03FF),
    ("greek_extended", 0x1F00, 0x1FFF),
    ("armenian", 0x0530, 0x058F),
    ("hebrew", 0x0590, 0x05FF),
    ("arabic", 0x0600, 0x06FF),
    ("han", 0x4E00, 0x9FFF),
    ("hangul", 0xAC00, 0xD7AF),
    ("hiragana_katakana", 0x3040, 0x30FF),
)


def _char_script(char: str) -> str:
    code = ord(char)
    if char.isascii():
        return "latin" if char.isalpha() else "none"
    if 0x00C0 <= code <= 0x024F:  # Latin-1 supplement + Latin extended
        return "latin"
    for name, low, high in _SCRIPT_RANGES:
        if low <= code <= high:
            return name
    return "other"


def leet_normalize(text: str) -> str:
    """Homoglyph fold + leet fold + hyphen strip, for brand comparisons only.

    Runs the confusable skeleton first so Cyrillic 'а' compares equal to 'a'
    (аpple-id.com must score like apple-id.com against the brand stems), then
    leet substitutions (paypa1 -> paypal).
    """
    folded = "".join(HOMOGLYPH_CONFUSABLES.get(char, char) for char in text.lower())
    return folded.replace("-", "").translate(LEET_TRANSLATION)


def homoglyph_skeleton(text: str) -> str:
    """Fold confusable non-ASCII characters to their ASCII lookalikes.

    A host whose skeleton differs from its literal form contains homoglyphs
    (xn-- punycode or raw non-ASCII): the classic аpple-id.com trick.
    """
    return "".join(HOMOGLYPH_CONFUSABLES.get(char, char) for char in text.lower())


def damerau_levenshtein_capped(a: str, b: str, cap: int = 8) -> int:
    """Damerau-Levenshtein distance (with transpositions), early-exited at cap.

    Used for brand typo-squatting distance; full unrestricted DL is not needed
    because anything beyond the cap carries no signal for the model.
    """
    if abs(len(a) - len(b)) > cap:
        return cap
    prev_prev: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        row_min = i
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            val = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            if (
                prev_prev is not None and i > 1 and j > 1
                and ca == b[j - 2] and a[i - 2] == cb
            ):
                val = min(val, prev_prev[j - 2] + 1)
            curr[j] = val
            row_min = min(row_min, val)
        if row_min >= cap:
            return cap
        prev_prev, prev = prev, curr
    return min(prev[len(b)], cap)


# Brand stems -> official registrable domains. Stem matching happens against
# the leet-normalized SLD and individual subdomain labels; the official-domain
# check keeps the real brand's own hosts (paypal.com) from being flagged as
# typo-squats of themselves.
BRAND_OFFICIAL_DOMAINS_V4: dict[str, str] = {
    "medium": "medium.com",
    "paypal": "paypal.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "spotify": "spotify.com",
    "notion": "notion.so",
    "figma": "figma.com",
    "slack": "slack.com",
    "zoom": "zoom.us",
    "atlassian": "atlassian.com",
    "dropbox": "dropbox.com",
    "microsoft": "microsoft.com",
    "office": "office.com",
    "outlook": "outlook.com",
    "onedrive": "onedrive.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "adobe": "adobe.com",
    "steam": "steampowered.com",
    "roblox": "roblox.com",
    "discord": "discord.com",
    "telegram": "telegram.org",
    "github": "github.com",
    "gitlab": "gitlab.com",
}

BRAND_STEMS_V4 = tuple(BRAND_OFFICIAL_DOMAINS_V4)

_OFFICIAL_DOMAIN_TO_STEM = {dom: stem for stem, dom in BRAND_OFFICIAL_DOMAINS_V4.items()}

_FOLDED_OFFICIAL_DOMAINS = {
    leet_normalize(dom.replace(".", "")) for dom in _OFFICIAL_DOMAIN_TO_STEM
}

_TOP1M_RANK_MAP: dict[str, int] | None = None

_TOP1M_PATH = Path(__file__).resolve().parents[1] / "ml" / "data" / "url_whitelist" / "top1m.txt"


def load_top1m_rank_map(path: Path = _TOP1M_PATH) -> dict[str, int]:
    """Ordered top-1M file -> {domain: best_rank} (line number = rank proxy).

    The committed list is rank-ordered (line 1 = rank 1) and mixes registrable
    domains with popular hosts (www.google.com, data.microsoft.com); the first
    occurrence of each name wins. This is the Tranco-rank stand-in for the
    `domain_rank_log` feature — swap in a real Tranco ranks file when one is
    available; the feature semantics (lower = more reputable) do not change.
    """
    global _TOP1M_RANK_MAP
    if _TOP1M_RANK_MAP is not None:
        return _TOP1M_RANK_MAP
    ranks: dict[str, int] = {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                dom = line.strip().lower().rstrip(".")
                if dom and dom not in ranks:
                    ranks[dom] = line_no
    except OSError:
        pass  # file missing in standalone contexts: every lookup falls back to UNKNOWN_RANK_LOG
    _TOP1M_RANK_MAP = ranks
    return ranks


def _rank_log_for(domain: str, registrable: str, rank_map: dict[str, int]) -> float:
    rank = rank_map.get(domain) or rank_map.get(registrable)
    return math.log10(rank) if rank else UNKNOWN_RANK_LOG


def _decode_punycode_label(label: str) -> str:
    """xn-- label -> Unicode form; returns the input unchanged on any failure."""
    if not label.lower().startswith(PUNYCODE_LABEL_PREFIX):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label


def _brand_signals(domain: str, registrable: str, labels: list[str]) -> dict:
    """Brand typo-squatting signals for the v4 feature block.

    All comparisons run on the leet-normalized form so paypa1-secure.tk folds
    to "paypalsecure" before the distance/prefix checks. The registrable
    domain's own SLD is compared, plus each non-registrable label (phishers
    park the brand in a subdomain: paypal.com.verify-id.tk).
    """
    norm_sld = leet_normalize(registrable.split(".")[0]) if registrable else ""
    norm_registrable = leet_normalize(registrable.replace(".", ""))
    sub_labels = [leet_normalize(l) for l in labels[:-2]] if len(labels) > 2 else []

    official = _OFFICIAL_DOMAIN_TO_STEM.get(registrable)
    min_distance = 8
    exact_leet = 0
    brand_in_nonofficial = 0

    for stem in BRAND_STEMS_V4:
        distance = damerau_levenshtein_capped(norm_sld, stem, cap=8)
        min_distance = min(min_distance, distance)
        if distance == 0 and norm_sld == stem:
            if official is None:
                # SLD is exactly a brand stem but this is not the brand's own
                # domain — leet-host phishing (paypa1.tk normalizes to paypal).
                exact_leet = 1
                brand_in_nonofficial = 1
        # Brand parked in a subdomain label (paypal.com.verify-id.tk) or as the
        # SLD prefix with extra junk (paypalsecure-login.tk).
        if stem in sub_labels or (official is None and norm_sld.startswith(stem)):
            brand_in_nonofficial = 1

    # A registrable domain that leet-folds onto a brand's full domain
    # (goog1e.com -> "googlecom") is the strongest single signal.
    if official is None and norm_registrable in _FOLDED_OFFICIAL_DOMAINS:
        exact_leet = 1
        brand_in_nonofficial = 1

    return {
        "brand_typo_min_distance": float(min_distance),
        "brand_typo_exact_leet": float(exact_leet),
        "brand_in_nonofficial_domain": float(brand_in_nonofficial),
    }


def shannon_entropy_v3(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _registrable(domain: str) -> str:
    """Registrable domain via the runtime reputation service (ccTLD-aware).

    Falls back to the last two labels only if the app package is not
    importable (standalone script usage outside the backend directory).
    """
    try:
        from app.core.url_reputation import get_registrable_domain

        return get_registrable_domain(domain)
    except Exception:
        parts = [p for p in domain.split(".") if p]
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def extract_url_features_v3(url: str, top_1m_domains: set) -> dict:
    """Flat feature dict for one URL. `top_1m_domains` must be a set of
    registrable domains (see load_top1m_domain_set) for O(1) membership."""
    try:
        parsed = urlparse(url)
    except ValueError:
        parsed = urlparse(f"http://{url}")

    domain = (parsed.hostname or "").strip().lower()
    path = parsed.path or ""
    query = parsed.query or ""

    is_top_1m = 1 if (_registrable(domain) in top_1m_domains or domain in top_1m_domains) else 0

    domain_digits = sum(c.isdigit() for c in domain)
    domain_alnum = sum(c.isalnum() for c in domain)

    labels = [p for p in domain.split(".") if p]
    num_subdomains = max(0, len(labels) - 2)

    try:
        from app.services.url_token_classifier import analyze_url_structure
        structure = analyze_url_structure(url)
        has_token = structure.get("has_structured_token", False)
        clean_domain = structure.get("domain_is_clean", False)
    except Exception:
        has_token = False
        clean_domain = False

    q_entropy = shannon_entropy_v3(query)
    p_entropy = shannon_entropy_v3(path)
    p_length = float(len(path))
    q_length = float(len(query))
    tot_length = float(len(url))

    if has_token and clean_domain:
        # CRITICAL RULE (T2): If structured token and domain is clean,
        # query_entropy and path_length must be heavily down-weighted.
        q_entropy *= 0.1
        p_length *= 0.1
        q_length *= 0.1
        p_entropy *= 0.1
        tot_length = float(min(tot_length, float(len(domain) + len(parsed.scheme or "http") + 25)))

    return {
        "is_top_1m": float(is_top_1m),
        "domain_entropy": shannon_entropy_v3(domain),
        "path_entropy": p_entropy,
        "query_entropy": q_entropy,
        "domain_length": float(len(domain)),
        "path_length": p_length,
        "query_length": q_length,
        "total_length": tot_length,
        "has_tracking_params": 1.0 if TRACKING_PARAM_PATTERN.search(query) else 0.0,
        "num_query_params": float(query.count("&") + 1) if query else 0.0,
        "has_ip": 1.0 if IP_HOST_PATTERN.match(domain) else 0.0,
        "num_dots": float(domain.count(".")),
        "num_subdomains": float(num_subdomains),
        # '@' credential trick lives in the authority (userinfo@host), not in
        # the path — benign user-profile URLs (medium.com/@handle) must NOT trip it.
        "has_at_symbol": 1.0 if "@" in parsed.netloc else 0.0,
        "suspicious_tld": 1.0 if (labels and labels[-1].lower() in SUSPICIOUS_TLDS_V3) else 0.0,
        "http_only": 1.0 if parsed.scheme == "http" else 0.0,
        "domain_digit_ratio": domain_digits / domain_alnum if domain_alnum else 0.0,
        "domain_hyphens": float(domain.count("-")),
        "has_suspicious_path_keyword": 1.0 if CREDENTIAL_PATH_PATTERN.search(path) else 0.0,
        "has_structured_token": 1.0 if has_token else 0.0,
        "domain_is_clean": 1.0 if clean_domain else 0.0,
    }


def vectorize_v3(features: dict) -> list[float]:
    """Flat dict -> fixed-order float vector (FEATURE_COLUMNS_V3 order)."""
    return [float(features[col]) for col in FEATURE_COLUMNS_V3]



def extract_url_features_v4(
    url: str,
    top_1m_domains: set,
    rank_map: dict[str, int] | None = None,
) -> dict:
    """v4 feature dict: the frozen legacy v3 keys plus the IDN/homoglyph and
    brand typo-squatting block.

    `rank_map` is optional for callers that already loaded the ordered top-1M
    ranks (load_top1m_rank_map); it is loaded lazily otherwise.
    """
    features = extract_url_features_v3(url, top_1m_domains)

    try:
        parsed = urlparse(url)
    except ValueError:
        parsed = urlparse(f"http://{url}")
    domain = (parsed.hostname or "").strip().lower().rstrip(".")
    registrable = _registrable(domain)
    labels = [p for p in domain.split(".") if p]

    # --- IDN / punycode ---
    is_idn = any(not ch.isascii() for ch in domain)
    puny_labels = [l for l in labels if l.lower().startswith(PUNYCODE_LABEL_PREFIX)]
    decoded_labels = [_decode_punycode_label(l) for l in labels]

    # Mixed-script detection runs on the *decoded* host: xn-- labels hide the
    # second script until decoded (xn--80ak6aa92e.com -> аpple.com).
    scripts = set()
    for label in decoded_labels:
        for ch in label:
            script = _char_script(ch)
            if script != "none":
                scripts.add(script)
    mixed_script = 1 if len(scripts) > 1 else 0

    # --- Homoglyph ---
    skeleton = homoglyph_skeleton("".join(decoded_labels))
    homoglyph_confusable = 1 if skeleton != "".join(decoded_labels).lower() else 0

    # --- Brand typo-squatting ---
    brand_signals = _brand_signals(domain, registrable, labels)

    # --- Rank proxy + extended TLDs ---
    ranks = rank_map if rank_map is not None else load_top1m_rank_map()
    tld = labels[-1].lower() if labels else ""

    features.update({
        "is_idn": 1.0 if is_idn else 0.0,
        "is_punycode": 1.0 if puny_labels else 0.0,
        "punycode_label_count": float(len(puny_labels)),
        "mixed_script_domain": float(mixed_script),
        "homoglyph_confusable": float(homoglyph_confusable),
        **brand_signals,
        "domain_rank_log": _rank_log_for(domain, registrable, ranks),
        "suspicious_tld_extended": 1.0 if tld in EXPANDED_SUSPICIOUS_TLDS_V4 else 0.0,
    })
    return features


def vectorize_v4(features: dict) -> list[float]:
    """Flat dict -> fixed-order float vector (FEATURE_COLUMNS_V4 order).

    The first 19 entries are byte-identical to vectorize_v3's output, so a v4
    vector can be truncated to feed the legacy v3.1 model in a pinch.
    """
    return [float(features[col]) for col in FEATURE_COLUMNS_V4]
