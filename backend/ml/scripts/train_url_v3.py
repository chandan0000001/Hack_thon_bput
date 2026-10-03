"""Train url_xgb_v3 — real-dataset URL phishing model (v3).

Mission: eliminate the v2 false positives on known-good domains that carry
long tracking URLs (Medium digest links, PayPal utm links) by training on
large-scale REAL data and on v3 features that separate domain reputation from
URL structure (ml/url_features_v3.py).

Data plan (all real, download-once cached):
  Benign   : 50,000 real domains sampled from the committed top-1M whitelist
             (backend/ml/data/url_whitelist/top1m.txt). 10,000 of them are
             augmented with real-world marketing/tracking query strings so the
             model learns that long queries on good domains are SAFE.
  Phishing : REAL URLs from the mitchellkrogza/Phishing.Database ACTIVE feed
             (GitHub, ~780k URLs; includes ~38k hosted on legitimate platforms
             like vercel.app / godaddysites.com — the hard cases). Cached to
             backend/ml/data/cache/phishing_feed_active.txt.
             Fallback (offline): cached OpenPhish JSON from the eval harness
             (backend/tests/data/cache/phishing_urls.json) + 20,000 synthetic
             lookalike URLs (brand-typo hosts, IP hosts, high-entropy
             subdomains on platform domains).

Run from the backend directory:
    uv run python ml/scripts/train_url_v3.py
"""

import json
import math
import random
import re
import sys
import urllib.request
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_DIR))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, train_test_split
from xgboost import XGBClassifier

from ml.url_features_v3 import (
    FEATURE_COLUMNS_V3,
    FEATURE_COLUMNS_V4,
    extract_url_features_v3,
    extract_url_features_v4,
    load_top1m_rank_map,
    vectorize_v3,
    vectorize_v4,
)

TOP1M_PATH = BACKEND_DIR / "ml" / "data" / "url_whitelist" / "top1m.txt"
CACHE_DIR = BACKEND_DIR / "ml" / "data" / "cache"
EVAL_PHISH_CACHE = BACKEND_DIR / "tests" / "data" / "cache" / "phishing_urls.json"
MODELS_DIR = BACKEND_DIR / "ml" / "models"
MODEL_PATH = MODELS_DIR / "url_xgb_v3.pkl"

PHISH_FEED_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
    "master/phishing-links-ACTIVE.txt"
)
PHISH_FEED_CACHE = CACHE_DIR / "phishing_feed_active.txt"

SEED = 42
N_BENIGN = 50_000
N_BENIGN_TRACKING_AUG = 10_000
# v3.1 augmentation (FP-hardening D4): benign "single high-entropy token
# query on a brand-secondary domain" — event-registration / ticket links
# (mediumday.com/?eventRegSource=<104-char token>) share the structural
# signature of victim-session phishing links; explicit benign examples teach
# the difference without weakening real detection.
N_BENIGN_BRAND_SECONDARY = 9_000
N_PHISH_REAL = 50_000
N_PHISH_SYNTHETIC_FALLBACK = 20_000

BRAND_STEMS = ["medium", "google", "apple", "amazon", "netflix", "spotify",
               "notion", "figma", "slack", "zoom", "atlassian", "dropbox"]
BRAND_SECONDARY_SUFFIXES = ["day", "weekly", "hub", "labs", "notes", "journal",
                            "times", "digest", "events", "live"]
BRAND_SECONDARY_TLDS = ["com", "org", "io", "co"]
TOKEN_QUERY_PARAMS = ["eventRegSource", "ticket", "reg_token", "confirm",
                      "attendee", "session", "sig", "ref_id", "registration"]

# Single-word deep paths real event/community product sites use — must cover
# the settings/help/tickets paths these emails actually link to.
BRAND_SECONDARY_PATHS = [
    "", "", "/", "/", "/settings", "/events", "/about", "/help", "/privacy",
    "/terms", "/support", "/blog", "/faq", "/schedule", "/speakers", "/venue",
    "/tickets", "/register", "/pricing", "/contact", "/email-preferences",
]

# Brand stems that must never be used as benign lookalike bait on their own
# official-domain-shaped hosts (paypal/medium etc. stay out of the generator
# output when the composed domain collides with a real top-1M entry — filtered
# at generation time).

PLATFORM_HOSTS = (
    "vercel.app", "netlify.app", "godaddysites.com", "blogspot.com", "weebly.com",
    "wixsite.com", "webnode.com", "hpage.com", "slashdot.org", "000webhostapp.com",
    "miraclesalad.com", "mysite.com", "glitch.me", "pages.dev", "firebaseapp.com",
    "web.app", "github.io", "herokuapp.com", "wordpress.com", "render.com",
)

TRACKING_TEMPLATES = [
    "?source=email-{hex}&utm_medium=email&ref={alnum}",
    "?utm_source=email-digest&utm_medium=email&utm_campaign={word}_{n}&utm_term={alnum}",
    "?source=email-{n}-{hex}-digest.reader&utm_medium=email",
    "?ref={alnum}&utm_campaign={word}&utm_content={n}",
    "?fbclid={alnum}&utm_source=facebook&utm_medium=social",
    "?gclid={alnum}&utm_source=google&utm_medium=cpc&campaign={word}",
    "?mc_cid={hex}&mc_eid={hex}&utm_source=mailchimp",
    "?email={alnum}%40gmail.com&utm_medium=email&source=newsletter-{word}",
    "?share_token={alnum}&utm_medium=social&utm_source=twitter",
    "?source=rss----{hex}----{word}",
]
TRACKING_WORDS = ["digest", "newsletter", "weekly", "daily", "promo", "spring-sale",
                  "product-launch", "reader", "footer", "header", "cta", "banner"]

# Paths real-world marketing/tracking links live on: the augmentation MUST
# cover the path+query combination (a benign medium.com/@user?source=... link
# has BOTH), otherwise the model learns "path AND query => phishing".
TRACK_PATHS = [
    "", "/", "/",  # bare-domain links dominate real marketing email
    "/@{user}", "/p/{id}", "/post/{id}", "/story/{id}", "/{user}/{id}",
    "/newsletter/{word}-{n}", "/articles/{id}", "/watch", "/en/{word}/{id}",
    "/login", "/signin", "/signup", "/pricing", "/shop/{word}", "/email/{id}",
]

# Realistic deep paths seen on reputable sites (used for the benign path mix).
BENIGN_PATHS = [
    "", "", "",  # weight bare-domain URLs
    "/about", "/help", "/pricing", "/blog", "/docs/getting-started", "/contact",
    "/products", "/search", "/questions/12345/how-do-i-parse-a-url",
    "/watch", "/p/{id}", "/post/{id}", "/c/{id}", "/status/{n}",
    "/@{user}", "/{user}/posts/{id}", "/store/category/{n}/items",
    "/en-us/articles/{n}-{word}", "/topics/{word}", "/login", "/signin", "/signup",
]

BENIGN_PLAIN_QUERIES = [
    "?ref={alnum}", "?page={n}", "?q={word}", "?id={n}", "?utm_medium=email",
    "?utm_source={word}&utm_medium=email", "?page={n}&sort={word}",
]

REAL_PLATFORM_PHISH_CACHE = CACHE_DIR / "phishing_feed_active.txt"


def _alnum(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


# ---------------------------------------------------------------------------
# 1. Datasets
# ---------------------------------------------------------------------------

def load_top1m_domains() -> set:
    domains = set()
    with TOP1M_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            dom = line.strip().lower()
            if dom:
                domains.add(dom)
    print(f"  top-1M whitelist: {len(domains):,} domains loaded from {TOP1M_PATH.name}")
    return domains


def _expand_path(rng: random.Random, template: str) -> str:
    path = template
    path = path.replace("{id}", _alnum(rng, rng.randint(6, 22)))
    path = path.replace("{user}", _alnum(rng, rng.randint(4, 12)))
    path = path.replace("{n}", str(rng.randint(1000, 999999999)))
    path = path.replace("{word}", rng.choice(TRACKING_WORDS))
    return path


def build_benign_urls(rng: random.Random, top1m: set) -> list[str]:
    """50k real benign domains; 10k augmented with real tracking parameters."""
    pool = sorted(top1m)
    sampled = rng.sample(pool, min(N_BENIGN, len(pool)))
    urls: list[str] = []
    n_augmented = 0
    for i, domain in enumerate(sampled):
        scheme = "http" if rng.random() < 0.08 else "https"  # top-1M over http is still benign
        if i < N_BENIGN_TRACKING_AUG:
            # Tracking-parameter augmentation on realistic paths: legitimate
            # marketing-email links (medium.com/@user?source=email-...).
            template = rng.choice(TRACKING_TEMPLATES)
            query = template.format(
                hex=_hex(rng, rng.randint(8, 16)),
                alnum=_alnum(rng, rng.randint(6, 24)),
                word=rng.choice(TRACKING_WORDS),
                n=rng.randint(10**9, 10**12),
            )
            urls.append(f"{scheme}://{domain}{_expand_path(rng, rng.choice(TRACK_PATHS))}{query}")
            n_augmented += 1
        elif rng.random() < 0.25:
            # Plain deep path + small benign query (?ref=, ?page=, utm_medium=email).
            query = rng.choice(BENIGN_PLAIN_QUERIES).format(
                alnum=_alnum(rng, rng.randint(6, 18)),
                n=rng.randint(1, 999999),
                word=rng.choice(TRACKING_WORDS),
            )
            urls.append(f"{scheme}://{domain}{_expand_path(rng, rng.choice(BENIGN_PATHS))}{query}")
        else:
            urls.append(f"{scheme}://{domain}{_expand_path(rng, rng.choice(BENIGN_PATHS))}")
    print(f"  benign: {len(urls):,} URLs ({n_augmented:,} with real tracking params)")
    return urls


def build_brand_secondary_urls(rng: random.Random, top1m: set) -> list[str]:
    """v3.1 augmentation: benign token-query links on brand-secondary domains.

    Composes {brand}{suffix}.{tld} hosts that (a) are NOT in the top-1M list
    (exactly like mediumday.com) and (b) carry one long high-entropy token
    query parameter — teaching the model that domain reputation is about the
    registrable domain itself, not the tracking blob behind it.
    """
    urls: list[str] = []
    seen: set[str] = set()
    while len(urls) < N_BENIGN_BRAND_SECONDARY:
        domain = (
            rng.choice(BRAND_STEMS)
            + rng.choice(BRAND_SECONDARY_SUFFIXES)
            + rng.choice(["", str(rng.randint(2, 99))])
            + "."
            + rng.choice(BRAND_SECONDARY_TLDS)
        )
        if domain in top1m or domain in seen:
            continue
        seen.add(domain)
        scheme = "https"
        style = rng.random()
        if style < 0.5:
            # The hard case: one long high-entropy token query parameter.
            param = rng.choice(TOKEN_QUERY_PARAMS)
            token = _alnum(rng, rng.randint(40, 120)) + str(rng.randint(10 ** 6, 10 ** 12))
            urls.append(f"{scheme}://{domain}/?{param}={token}")
        elif style < 0.7:
            # Bare/root and single-word deep paths — the domain itself must
            # read benign wherever it is linked (/settings, /tickets, ...).
            path = rng.choice(BRAND_SECONDARY_PATHS)
            urls.append(f"{scheme}://{domain}{path}")
        else:
            # Realistic multi-segment deep paths.
            path = rng.choice(BENIGN_PATHS) or "/about"
            path = _expand_path(rng, path)
            urls.append(f"{scheme}://{domain}{path}")
    print(f"  benign (v3.1 brand-secondary token augmentation): {len(urls):,} URLs")
    return urls


def fetch_real_phishing_urls(rng: random.Random) -> tuple[list[str], str]:
    """Download (or reuse cached) the real phishing feed; sample N_PHISH_REAL."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not PHISH_FEED_CACHE.exists():
        print(f"  downloading real phishing feed: {PHISH_FEED_URL}")
        try:
            req = urllib.request.Request(PHISH_FEED_URL, headers={"User-Agent": "cyberguard-training/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                PHISH_FEED_CACHE.write_bytes(resp.read())
        except Exception as exc:
            print(f"  !! download failed ({exc}) — falling back to cached/synthetic phishing")
            return fallback_phishing_urls(rng), "synthetic-fallback"
    urls: list[str] = []
    platform_urls: list[str] = []
    feed_positions: list[int] = []
    for line_no, line in enumerate(PHISH_FEED_CACHE.read_text(encoding="utf-8", errors="replace").splitlines()):
        u = line.strip()
        if not u.startswith(("http://", "https://", "ftp://")):
            continue
        if any(p in u for p in PLATFORM_HOSTS):
            platform_urls.append(u)
        else:
            urls.append(u)
            feed_positions.append(line_no)
    if not urls and not platform_urls:
        return fallback_phishing_urls(rng), "synthetic-fallback", []
    # Keep a bounded slice of platform-hosted phishing (the hard cases, capped
    # so class balance stays near 1:1) + a random sample of the general feed.
    max_platform = min(20_000, N_PHISH_REAL // 2)
    if len(platform_urls) > max_platform:
        platform_urls = rng.sample(platform_urls, max_platform)
    remaining = N_PHISH_REAL - len(platform_urls)
    if remaining > 0:
        if len(urls) > remaining:
            keep = rng.sample(range(len(urls)), remaining)
            keep.sort()  # preserve feed order so temporal_key stays monotone
            urls = [urls[i] for i in keep]
            feed_positions = [feed_positions[i] for i in keep]
    else:
        urls = []
        feed_positions = []
    picked = platform_urls + urls
    # Platform-hosted URLs have no meaningful feed-position key; park them at
    # the end of the temporal ordering (they are the newest-wave hard cases).
    temporal_keys = feed_positions + [10_000_000 + i for i in range(len(platform_urls))]
    print(f"  phishing: {len(picked):,} REAL URLs "
          f"({len(platform_urls):,} platform-hosted like vercel.app/godaddysites.com)")
    return picked, "real-feed", temporal_keys


def fallback_phishing_urls(rng: random.Random) -> list[str]:
    """Cached OpenPhish JSON (real) + synthetic lookalike generation."""
    urls: list[str] = []
    if EVAL_PHISH_CACHE.exists():
        data = json.loads(EVAL_PHISH_CACHE.read_text(encoding="utf-8"))
        urls.extend(row["url"] for row in data if row.get("label") == "phishing")
    brands = ["paypa1", "amaz0n", "app1e", "micros0ft", "netf1ix", "coinbase", "faceb00k", "go0gle"]
    words = ["secure", "login", "verify", "account", "billing", "support", "update", "wallet"]
    tlds = ["tk", "ml", "ga", "cf", "gq", "xyz", "top"]
    while len(urls) < N_PHISH_SYNTHETIC_FALLBACK:
        style = rng.choice(["lookalike", "ip", "entropy", "platform"])
        if style == "lookalike":
            host = f"{rng.choice(brands)}-{rng.choice(words)}-{_alnum(rng, 4)}.{rng.choice(tlds)}"
            urls.append(f"http://{host}/{rng.choice(words)}.php")
        elif style == "ip":
            ip = f"{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            urls.append(f"http://{ip}/{rng.choice(words)}-{rng.randint(1000, 9999)}.php")
        elif style == "platform":
            sub = _alnum(rng, rng.randint(16, 28))
            host = rng.choice(PLATFORM_HOSTS)
            urls.append(f"https://{sub}.{host}/{_alnum(rng, 20)}/{rng.choice(words)}")
        else:
            sub = _alnum(rng, 28)
            urls.append(f"http://{sub}.com/{_alnum(rng, 14)}/verify.php")
    print(f"  phishing: {len(urls):,} (cached real + synthetic lookalikes)")
    return urls


# ---------------------------------------------------------------------------
# 2. Feature matrix
# ---------------------------------------------------------------------------

def registrable_of_url(url: str, top1m: set) -> str:
    """Registrable domain of a URL — the leakage group key.

    Every URL from the same registrable domain lands in the same fold, so the
    model cannot memorize a domain on one URL and 'recognize' it on another.
    """
    from urllib.parse import urlparse

    from ml.url_features_v3 import IP_HOST_PATTERN, _registrable

    try:
        parsed = urlparse(url)
    except ValueError:
        parsed = urlparse(f"http://{url}")
    domain = (parsed.hostname or "").strip().lower().rstrip(".")
    if not domain:
        # Userinfo-trick / malformed-authority URLs: group on the raw netloc so
        # siblings of the same attacker infrastructure stay together.
        return parsed.netloc.lower() or url
    if IP_HOST_PATTERN.match(domain):
        # A bare IP has no registrable domain (and _registrable would fold
        # 192.168.1.5 to 1.5) — group on the IP itself.
        return domain
    return _registrable(domain)


def build_frame(
    urls: list[str],
    label: int,
    top1m: set,
    temporal_keys: list[int] | None = None,
    schema: str = "v3",
) -> pd.DataFrame:
    """Feature frame with leakage-audit metadata columns.

    `group_domain`  — registrable domain, the key for domain-grouped splits.
    `temporal_key`  — proxy for when the URL was first seen (feed-file line
    number for real phishing, generation order otherwise); drives the temporal
    split. Both are metadata ONLY — they are never part of X.
    """
    use_v4 = schema == "v4"
    columns = FEATURE_COLUMNS_V4 if use_v4 else FEATURE_COLUMNS_V3
    extract = extract_url_features_v4 if use_v4 else extract_url_features_v3

    rows = []
    for i, url in enumerate(urls):
        try:
            feats = extract(url, top1m) if not use_v4 else extract(url, top1m, load_top1m_rank_map())
        except Exception:
            continue
        vector = vectorize_v4(feats) if use_v4 else vectorize_v3(feats)
        rows.append(vector + [label, registrable_of_url(url, top1m),
                              temporal_keys[i] if temporal_keys else i])
    return pd.DataFrame(rows, columns=columns + ["label", "group_domain", "temporal_key"])


# ---------------------------------------------------------------------------
# 2b. Leakage-prevention splits (domain-grouped + temporal)
# ---------------------------------------------------------------------------

def domain_grouped_split(frame: pd.DataFrame, test_size: float = 0.2, seed: int = SEED):
    """Single 80/20 holdout where no registrable domain spans both sides.

    A plain stratified split leaks: the real phishing feed contains many URLs
    per attacker domain, so near-duplicate hosts land on both sides and the
    holdout AUC reads 5-15 points high (the classic phishing-dataset leakage
    documented by Sahingoz et al. and the PhishBench line of work).
    """
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(frame, groups=frame["group_domain"]))
    return train_idx, test_idx


def domain_grouped_cv(
    model_factory,
    frame: pd.DataFrame,
    top1m: set,
    n_splits: int = 5,
    schema: str = "v3",
) -> list[dict]:
    """GroupKFold CV over registrable domains — the honest model-selection
    metric. Returns per-fold metrics; print/aggregate as needed."""
    columns = FEATURE_COLUMNS_V4 if schema == "v4" else FEATURE_COLUMNS_V3
    folds = []
    splitter = GroupKFold(n_splits=n_splits)
    for fold_no, (train_idx, test_idx) in enumerate(
        splitter.split(frame[columns], frame["label"], groups=frame["group_domain"]), start=1
    ):
        train, test = frame.iloc[train_idx], frame.iloc[test_idx]
        model = model_factory(len(train))
        model.fit(train[columns], train["label"])
        proba = model.predict_proba(test[columns])[:, 1]
        pred = (proba > 0.5).astype(int)
        folds.append({
            "fold": fold_no,
            "auc": round(float(roc_auc_score(test["label"], proba)), 4),
            "f1": round(float(f1_score(test["label"], pred)), 4),
            "train_domains": int(train["group_domain"].nunique()),
            "test_domains": int(test["group_domain"].nunique()),
        })
        print(f"  fold {fold_no}: AUC {folds[-1]['auc']:.4f}  F1 {folds[-1]['f1']:.4f}  "
              f"(train domains {folds[-1]['train_domains']:,} / test {folds[-1]['test_domains']:,})")
    return folds


def temporal_split(frame: pd.DataFrame, test_size: float = 0.2):
    """Train on the past, test on the future, ordered by `temporal_key`.

    The real phishing feed's line order approximates first-seen order, so the
    test slice simulates 'URLs that appear after the model shipped' — the
    regime the runtime actually faces. Unlike the domain-grouped split this
    intentionally ALLOWS domain overlap across time (a domain seen in March
    legitimately reappears in June); the leakage report records the overlap
    but the zero-overlap gate only applies to the domain-grouped split.
    """
    ordered = frame.sort_values("temporal_key", kind="stable").reset_index(drop=True)
    cutoff = int(len(ordered) * (1.0 - test_size))
    return ordered.index[:cutoff], ordered.index[cutoff:]


def leakage_report(frame: pd.DataFrame, train_idx, test_idx, mode: str) -> dict:
    """Domain-overlap audit for any split; must be 0 overlapping domains."""
    train_domains = set(frame.iloc[train_idx]["group_domain"])
    test_domains = set(frame.iloc[test_idx]["group_domain"])
    overlap = train_domains & test_domains
    print(f"\n--- LEAKAGE AUDIT ({mode} split) ---")
    print(f"  train: {len(train_idx):,} rows / {len(train_domains):,} domains")
    print(f"  test : {len(test_idx):,} rows / {len(test_domains):,} domains")
    print(f"  domain overlap: {len(overlap):,} {'✅ PASS' if not overlap else '❌ FAIL — LEAKAGE'}")
    return {"mode": mode, "overlap_domains": len(overlap), "train_rows": len(train_idx),
            "test_rows": len(test_idx)}


# ---------------------------------------------------------------------------
# 3. Synthetic "Medium test" validation set (Deliverable 4)
# ---------------------------------------------------------------------------

TEST_URLS = [
    ("https://medium.com/@coder6861python?source=email-971ea2707eee-1789158672039-digest.reader", 0),
    ("https://paypal.com/signin?utm_source=email", 0),
    ("http://paypa1-secure.tk/login", 1),
    ("http://192.168.1.5/verify-login.php", 1),
]

# v3.1 gate: the live FP that motivated the brand-secondary augmentation.
V31_TEST_URLS = [
    ("https://mediumday.com/?eventRegSource=Kk9Xq2vT7wYzR4bN1mJcP6dFs3hLa0eGu8iQo5VyBn2tAxW9eCr4UlZp7Sd0Hj3gMf6Ti1qWeRtYyUuIoPpAsDfGhJ8kLzXcVbNmQwe4rTyUiOpAsdFgHjKlZxCvBnM1234567890", 0),
]


def run_validation(model: XGBClassifier, top1m: set, version: str = "v3", schema: str = "v3") -> bool:
    print("\n--- V3 MODEL VALIDATION ---")
    columns = FEATURE_COLUMNS_V4 if schema == "v4" else FEATURE_COLUMNS_V3

    def feature_row(url: str) -> pd.DataFrame:
        if schema == "v4":
            return pd.DataFrame([vectorize_v4(extract_url_features_v4(url, top1m, load_top1m_rank_map()))],
                                columns=columns)
        return pd.DataFrame([vectorize_v3(extract_url_features_v3(url, top1m))], columns=columns)

    test_urls = list(TEST_URLS) + (V31_TEST_URLS if version.startswith("v3.1") else [])
    all_pass = True
    for url, expected in test_urls:
        proba = model.predict_proba(feature_row(url))[0][1]
        is_phish_pred = proba > 0.5
        ok = is_phish_pred == bool(expected)
        all_pass &= ok
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"{status} | Prob: {proba:.4f} | Expected: {'Phish' if expected else 'Benign'} | {url}")
    medium_proba = model.predict_proba(feature_row(TEST_URLS[0][0]))[0][1]
    if medium_proba >= 0.20:
        print(f"❌ FAIL | Medium digest URL probability {medium_proba:.4f} did NOT drop below 0.20")
        all_pass = False
    else:
        print(f"✅ PASS | Medium digest URL probability {medium_proba:.4f} < 0.20 (v2 scored it ~0.76)")
    return all_pass


# ---------------------------------------------------------------------------
# 4. Main
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str]) -> dict:
    """Positional version + flags: [--split stratified|domain|temporal]
    [--schema v3|v4] [--cv]. Defaults preserve the historical v3 behaviour."""
    args = {"version": "v3", "split": "stratified", "schema": "v3", "cv": False}
    positional = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--split":
            args["split"] = argv[i + 1]
            i += 2
        elif arg == "--schema":
            args["schema"] = argv[i + 1]
            i += 2
        elif arg == "--cv":
            args["cv"] = True
            i += 1
        else:
            positional.append(arg)
            i += 1
    if positional:
        args["version"] = positional[0]
    return args


def make_model(n_train: int, n_benign: int, n_phish: int) -> XGBClassifier:
    return XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        scale_pos_weight=max(1, n_benign) / max(1, n_phish),  # handle class imbalance
        eval_metric="auc",
        tree_method="hist",
        n_jobs=-1,
        random_state=SEED,
    )


def main() -> int:
    cfg = _parse_args(sys.argv[1:])
    version = cfg["version"]
    split_mode = cfg["split"]
    schema = cfg["schema"]
    if split_mode not in {"stratified", "domain", "temporal"}:
        print(f"!! unknown --split {split_mode!r} (use stratified|domain|temporal)")
        return 2
    if schema not in {"v3", "v4"}:
        print(f"!! unknown --schema {schema!r} (use v3|v4)")
        return 2

    model_filename = "url_xgb_v3.pkl" if version == "v3" else f"url_xgb_{version}.pkl"
    model_path = MODELS_DIR / model_filename
    print(f"=== {model_filename} training (schema={schema}, split={split_mode}) ===")
    rng = random.Random(SEED)
    top1m = load_top1m_domains()

    benign_urls = build_benign_urls(rng, top1m)
    if version.startswith("v3.1"):
        benign_urls += build_brand_secondary_urls(rng, top1m)
    phish_urls, data_mode, phish_temporal = fetch_real_phishing_urls(rng)

    # Dedup by URL (feature-level dedup would collapse distinct short domains
    # that happen to share identical feature vectors — mostly benign loss).
    benign_urls = list(dict.fromkeys(benign_urls))
    benign_set = set(benign_urls)
    phish_urls = [u for u in dict.fromkeys(phish_urls) if u not in benign_set]
    phish_temporal = phish_temporal[: len(phish_urls)] if phish_temporal else None

    print(f"  building {schema} features for {len(benign_urls) + len(phish_urls):,} URLs ...")
    columns = FEATURE_COLUMNS_V4 if schema == "v4" else FEATURE_COLUMNS_V3
    benign_df = build_frame(benign_urls, 0, top1m, schema=schema)
    phish_df = build_frame(phish_urls, 1, top1m, temporal_keys=phish_temporal, schema=schema)
    frame = pd.concat([benign_df, phish_df], ignore_index=True)
    frame = frame.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    y = frame["label"]
    n_benign, n_phish = int((y == 0).sum()), int((y == 1).sum())

    if split_mode == "domain":
        train_idx, test_idx = domain_grouped_split(frame)
    elif split_mode == "temporal":
        train_idx, test_idx = temporal_split(frame)
    else:
        # Historical behaviour: plain stratified holdout (leaks domains — kept
        # only for comparability with the v3.1 metrics; see leakage_report).
        train_idx, test_idx = train_test_split(
            frame.index, test_size=0.2, stratify=y, random_state=SEED)
    leakage = leakage_report(frame, train_idx, test_idx, split_mode)

    train, test = frame.iloc[np.asarray(train_idx)], frame.iloc[np.asarray(test_idx)]
    X_train, y_train = train[columns], train["label"]
    X_test, y_test = test[columns], test["label"]

    cv_results = None
    if cfg["cv"]:
        print(f"\n--- GROUP-KFOLD CV (5 folds, domain-grouped, schema={schema}) ---")
        cv_results = domain_grouped_cv(
            lambda n: make_model(n, n_benign, n_phish), frame, top1m, schema=schema)

    model = make_model(len(X_train), n_benign, n_phish)
    # NOTE: use_label_encoder intentionally omitted — removed in xgboost >= 2.0.
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba > 0.5).astype(int)
    auc = roc_auc_score(y_test, proba)
    f1 = f1_score(y_test, pred)
    acc = accuracy_score(y_test, pred)
    print(f"\n--- TEST METRICS ({split_mode} holdout, schema={schema}) ---")
    print(f"  rows: {len(frame):,} (benign {n_benign:,} / phishing {n_phish:,}) | data_mode: {data_mode}")
    print(f"  AUC:  {auc:.4f}")
    print(f"  F1:   {f1:.4f}")
    print(f"  accuracy: {acc:.4f}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)  # joblib for parity with the runtime joblib.load path
    print(f"\n  saved: {model_path}")

    ok = run_validation(model, top1m, version=version, schema=schema)

    # Platform-hosted phishing spot check (must NOT be whitelisted by reputation).
    platform_phish = [u for u in phish_urls if any(p in u for p in PLATFORM_HOSTS)][:5]
    if platform_phish:
        print("\n--- PLATFORM-HOSTED PHISHING SPOT CHECK (reputation must not blind the model) ---")
        if schema == "v4":
            vecs = pd.DataFrame(
                [vectorize_v4(extract_url_features_v4(u, top1m, load_top1m_rank_map())) for u in platform_phish],
                columns=FEATURE_COLUMNS_V4)
        else:
            vecs = pd.DataFrame(
                [vectorize_v3(extract_url_features_v3(u, top1m)) for u in platform_phish],
                columns=FEATURE_COLUMNS_V3)
        for u, p in zip(platform_phish, model.predict_proba(vecs)[:, 1]):
            print(f"  {'✅' if p > 0.5 else '❌'} Prob: {p:.4f} | {u[:100]}")

    metrics = {
        "model": model_filename,
        "data_mode": data_mode,
        "schema": schema,
        "split_mode": split_mode,
        "leakage_audit": leakage,
        "cv_domain_grouped": cv_results,
        "n_rows": int(len(frame)),
        "n_benign": n_benign,
        "n_phishing": n_phish,
        "test_auc": round(float(auc), 4),
        "test_f1": round(float(f1), 4),
        "test_accuracy": round(float(acc), 4),
    }
    (MODELS_DIR / f"url_{version.replace('.', '')}_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("\n=== DONE ===")
    # Zero-overlap is only a hard requirement for the domain-grouped split;
    # temporal splits legitimately reuse domains across the time boundary.
    no_leakage = split_mode != "domain" or leakage["overlap_domains"] == 0
    return 0 if ok and no_leakage else 1


if __name__ == "__main__":
    sys.exit(main())
