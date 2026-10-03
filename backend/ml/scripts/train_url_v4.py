"""train_url_v4.py — the 29-feature extension model (cascaded Stage 1).

SUPERSEDES the previous plan in this file (a 19-feature "drop-in" retrain fed
by fetch_url_data.py -> preprocess_url_v4.py -> url_v4_processed.csv). That
pipeline never ran (no url_datasets/ CSV was ever produced) and the external
audits in ml/scripts/eval_url_models.py showed its premise — a feature lock at
19 columns — is exactly what the serving v3.1 model is missing: the 19-feature
schema cannot see punycode/IDN at all, and its benign corpus lacked real
enterprise subdomain shapes, which the external eval flagged as the dominant
false-positive class (FPR 33% on held-out top-1M domains).

Differences from v3.1 (all evidence-driven):

  FP class 1 — multi-hyphen enterprise subdomains
    (workflows-frontend-livechat.corporatetools.com scored 0.97 on the v3.1
    external eval): the benign corpus was bare registrable domains, so
    hyphen-heavy subdomains of REAL top-1M organizations look phishy.
    -> new benign generators: enterprise subdomains, accounts./auth./sso.
       OAuth/OIDC hosts, CDN/static asset hosts.

  FP class 2 — IDN/homoglyph and brand impersonation blindness
    -> FEATURE_COLUMNS_V4 (IDN, punycode count, mixed-script, homoglyph fold,
       brand typo distance vs ~39 stems, top-1M rank proxy, extended TLDs).

  FN class — shortener/open-redirect phish
    the daily feed contains almost no wrapped/redirected URLs.
    -> synthetic shortener-wrapped and open-redirect phishing.

Split: DOMAIN-GROUPED (no registrable domain spans train/test) — the
stratified holdout metrics that made v3.1 look near-perfect are inflated by
domain leakage and are no longer the gate.

Run from the backend directory:
    uv run python ml/scripts/train_url_v4.py
"""

import random
import string
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_DIR))

import json

import joblib
import pandas as pd
from sklearn.metrics import roc_auc_score

from ml.scripts.train_url_v3 import (
    MODELS_DIR,
    SEED,
    build_benign_urls,
    build_brand_secondary_urls,
    domain_grouped_split,
    fetch_real_phishing_urls,
    leakage_report,
    load_top1m_domains,
    make_model,
    registrable_of_url,
)
from ml.url_features_v3 import (
    FEATURE_COLUMNS_V4,
    extract_url_features_v4,
    load_top1m_rank_map,
    vectorize_v4,
)
from ml.scripts.eval_url_models import full_metrics

MODEL_PATH = MODELS_DIR / "url_xgb_v4.pkl"
METRICS_PATH = MODELS_DIR / "url_v4_metrics.json"

N_BENIGN_ENTERPRISE = 20_000
N_BENIGN_OAUTH = 8_000
N_BENIGN_CDN = 7_000
N_PHISH_SYNTH_V4 = 12_000

SUBDOMAIN_STEMS = ["portal", "app", "svc", "api", "mail", "docs", "static",
                   "assets", "cdn", "img", "media", "support", "status"]
OAUTH_STEMS = ["accounts", "auth", "login", "sso", "id", "signin"]
OAUTH_PATHS = [
    "/auth/realms/master/protocol/openid-connect/auth",
    "/o/oauth2/v2/auth",
    "/authorize",
    "/oauth2/authorize",
    "/signin",
    "/login",
]
OAUTH_QUERIES = [
    "?client_id={a}&response_type=code&scope=openid%20profile%20email&redirect_uri=https%3A%2F%2Fapp.{d}%2Fcb&state={b}",
    "?response_type=code&client_id={a}&prompt=login&state={b}",
    "?redirect_uri=https%3A%2F%2Fwww.{d}%2Fcallback&scope=email",
]

# Phishing shapes underrepresented in the daily feed.
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"]
BRAND_TARGETS = ["apple", "paypal", "microsoft", "netflix", "coinbase", "instagram"]
REDIRECT_PARAMS = ["url", "next", "redirect", "dest", "continue", "return", "target", "goto"]


def _alnum(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _word(rng: random.Random) -> str:
    return rng.choice(["spring", "digest", "weekly", "launch", "promo", "notes", "hub", "live"])


def build_enterprise_subdomain_urls(rng: random.Random, top1m: set) -> list[str]:
    """Benign multi-hyphen enterprise subdomains of real top-1M organizations.

    Directly targets the dominant external FP class: real infrastructure like
    workflows-frontend-livechat.corporatetools.com must never score phishy.
    """
    pool = sorted(top1m)
    urls = []
    for _ in range(N_BENIGN_ENTERPRISE):
        base = rng.choice(pool)
        if base.startswith("www."):
            base = base[4:]
        parts = rng.sample(SUBDOMAIN_STEMS, rng.randint(1, 2))
        if rng.random() < 0.4:
            parts.append(_alnum(rng, rng.randint(2, 5)))
        elif rng.random() < 0.5:
            parts.append(_word(rng))
        host = "-".join(parts) + "." + base
        path = rng.choice(["", "", "/", f"/{rng.choice(['status', 'health', 'api/v1', 'en', 'home'])}"])
        urls.append(f"https://{host}{path}")
    return list(dict.fromkeys(urls))


def build_oauth_sso_urls(rng: random.Random, top1m: set) -> list[str]:
    """Benign OAuth/OIDC/login URLs on subdomains of real top-1M domains.

    Credential-path keywords on a legitimate host are the classic heuristic
    FP; explicit benign examples teach the difference from fake-login phish.
    """
    pool = sorted(top1m)
    urls = []
    for _ in range(N_BENIGN_OAUTH):
        base = rng.choice(pool)
        if base.startswith("www."):
            base = base[4:]
        stem = rng.choice(OAUTH_STEMS)
        style = rng.random()
        if style < 0.6:
            url = f"https://{stem}.{base}{rng.choice(OAUTH_PATHS)}"
            url += rng.choice(OAUTH_QUERIES).format(a=_alnum(rng, 20), b=_alnum(rng, 12), d=base)
        elif style < 0.8:
            url = f"https://{stem}.{base}{rng.choice(['/signin', '/login', '/identify'])}?returnUrl=%2Fhome"
        else:
            url = f"https://www.{base}/login?redirect={_alnum(rng, 10)}"
        urls.append(url)
    return list(dict.fromkeys(urls))


def build_cdn_asset_urls(rng: random.Random, top1m: set) -> list[str]:
    """Benign CDN/static asset and deep-link URLs."""
    pool = sorted(top1m)
    urls = []
    for _ in range(N_BENIGN_CDN):
        base = rng.choice(pool)
        if base.startswith("www."):
            base = base[4:]
        style = rng.random()
        if style < 0.4:
            urls.append(f"https://cdn.{base}/assets/{_alnum(rng, 10)}.{rng.choice(['js', 'css', 'png', 'woff2'])}")
        elif style < 0.7:
            urls.append(f"https://static.{base}/{_word(rng)}/{_alnum(rng, 8)}/index.html")
        else:
            urls.append(f"https://www.{base}/{'/'.join(str(rng.randint(1, 9999)) for _ in range(rng.randint(2, 4)))}?page={rng.randint(1, 50)}")
    return list(dict.fromkeys(urls))


def _punycode_brand_host(rng: random.Random) -> str | None:
    """Homoglyph brand lookalike -> real punycode (xn--...) host.

    Substitutes a Cyrillic/Greek confusable into a brand name and encodes it
    exactly the way a real IDN attack does.
    """
    confusables = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
    brand = rng.choice(BRAND_TARGETS)
    poisoned = "".join(confusables[ch] if ch in confusables and rng.random() < 0.5 else ch for ch in brand)
    tld = rng.choice(["com", "net", "io", "app", "top"])
    label = poisoned if rng.random() < 0.5 else f"{poisoned}-{rng.choice(['secure', 'login', 'verify', 'id'])}"
    try:
        puny = label.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if puny == label:  # no non-ASCII survived -> not an IDN case
        return None
    return f"{puny}.{tld}"


def build_synthetic_phish_v4(rng: random.Random) -> list[str]:
    """Phishing diversity the feed lacks: IDN/punycode, shortener-wrapped,
    open-redirect chains, brand-hyphen login hosts."""
    urls = []
    tlds = ["tk", "ml", "top", "xyz", "cf", "gq", "rest", "cyou"]
    while len(urls) < N_PHISH_SYNTH_V4:
        style = rng.random()
        if style < 0.3:
            host = _punycode_brand_host(rng)
            if not host:
                continue
            urls.append(f"https://{host}/{rng.choice(['login', 'verify', 'secure', 'signin', ''])}")
        elif style < 0.55:
            short = rng.choice(SHORTENERS)
            evil = f"{rng.choice(BRAND_TARGETS)}-{rng.choice(['secure', 'login', 'verify'])}-{_alnum(rng, 4)}.{rng.choice(tlds)}"
            urls.append(f"https://{short}/{_alnum(rng, rng.randint(5, 9))}")  # wrapper itself
            urls.append(f"https://{evil}/{rng.choice(['wp-content', '', 'session'])}?{_alnum(rng, 6)}={_alnum(rng, 12)}")
        elif style < 0.8:
            # Open redirect on a plausible relay host pointing at a brand phish.
            relay = f"{_alnum(rng, 6)}.{rng.choice(['workers.dev', 'vercel.app', 'pages.dev', 'herokuapp.com'])}"
            evil = f"https://{rng.choice(BRAND_TARGETS)}-secure.{rng.choice(tlds)}/login"
            urls.append(f"https://{relay}/?{rng.choice(REDIRECT_PARAMS)}={evil}")
        else:
            # Brand-hyphen login host (pure-ASCII impersonation).
            brand = rng.choice(BRAND_TARGETS)
            host = f"{brand}-{rng.choice(['secure', 'login', 'account', 'verify', 'support'])}{rng.randint(1, 99)}.{rng.choice(tlds)}"
            urls.append(f"https://{host}/{rng.choice(['login.php', 'signin', 'verify/', ''])}")
    return list(dict.fromkeys(urls))[:N_PHISH_SYNTH_V4]


# Validation gates: v3 parity cases + v4-specific attack/benign cases.
V4_GATES = [
    ("https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&response_type=code", 0),
    ("https://login.microsoftonline.com/common/oauth2/authorize", 0),
    # Multi-hyphen enterprise subdomain on a benign registrable domain. NOTE:
    # the same shape on a PLATFORM host (portal-app-svc.cloudfront.net) is a
    # phishing pattern — platform hosts are deliberately NOT benign gates.
    ("https://portal-app-svc.corporatetools.com/status", 0),
    ("https://www.bbc.co.uk/news", 0),
    ("https://paypal.com/signin", 0),
    ("https://xn--80ak6aa92e.com/", 1),          # punycode homoglyph
    ("https://xn--pypal-4ve.com/login", 1),       # confusable punycode
    ("http://paypa1-secure.tk/login", 1),         # leet typo-squat
    ("https://bit.ly/3xR2f9K", None),             # shortener: informational only
]


def run_gates(model, top1m: set) -> tuple[bool, list[dict]]:
    ranks = load_top1m_rank_map()
    all_pass = True
    rows = []
    for url, expected in V4_GATES:
        feats = extract_url_features_v4(url, top1m, ranks)
        proba = model.predict_proba(pd.DataFrame([vectorize_v4(feats)], columns=FEATURE_COLUMNS_V4))[0][1]
        pred_phish = proba > 0.5
        ok = (expected is None) or (pred_phish == bool(expected))
        if expected is not None:
            all_pass &= ok
        rows.append({"url": url, "proba": round(float(proba), 4), "expected": expected,
                     "pass": bool(ok)})
        status = ("INFO" if expected is None else ("PASS" if ok else "FAIL"))
        print(f"  {status} | {proba:.4f} | {url[:80]}")
    return all_pass, rows


def v4_frame(urls: list[str], label: int, top1m: set, ranks: dict) -> pd.DataFrame:
    rows = []
    for url in urls:
        try:
            feats = extract_url_features_v4(url, top1m, ranks)
            rows.append(vectorize_v4(feats) + [label, registrable_of_url(url, top1m)])
        except Exception:
            continue
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS_V4 + ["label", "group_domain"])


def main() -> int:
    print("=== url_xgb_v4 training (29-feature schema, domain-grouped split) ===")
    rng = random.Random(SEED)
    top1m = load_top1m_domains()
    ranks = load_top1m_rank_map()

    benign_urls = build_benign_urls(rng, top1m)
    benign_urls += build_brand_secondary_urls(rng, top1m)
    benign_urls += build_enterprise_subdomain_urls(rng, top1m)
    benign_urls += build_oauth_sso_urls(rng, top1m)
    benign_urls += build_cdn_asset_urls(rng, top1m)

    phish_real, data_mode, phish_temporal = fetch_real_phishing_urls(rng)
    phish_urls = [u for u in dict.fromkeys(phish_real) if u not in set(benign_urls)]
    phish_urls += build_synthetic_phish_v4(rng)
    benign_urls = list(dict.fromkeys(benign_urls))
    print(f"  corpus: benign={len(benign_urls):,} phishing={len(phish_urls):,}")

    print("  building v4 features (29 columns) ...")
    benign_df = v4_frame(benign_urls, 0, top1m, ranks)
    phish_df = v4_frame(phish_urls, 1, top1m, ranks)
    frame = pd.concat([benign_df, phish_df], ignore_index=True)
    frame = frame.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    y = frame["label"]
    n_benign, n_phish = int((y == 0).sum()), int((y == 1).sum())

    tr, te = domain_grouped_split(frame)
    leakage = leakage_report(frame, tr, te, "domain")
    train, test = frame.iloc[tr], frame.iloc[te]

    model = make_model(len(train), n_benign, n_phish)
    model.fit(train[FEATURE_COLUMNS_V4], train["label"])

    proba = model.predict_proba(test[FEATURE_COLUMNS_V4])[:, 1]
    metrics = full_metrics(test["label"].to_numpy(), proba)
    if metrics["roc_auc"] is None:
        metrics["roc_auc"] = round(float(roc_auc_score(test["label"], proba)), 4)
    print("\n--- DOMAIN-GROUPED HOLDOUT ---")
    print(f"  rows={len(frame):,} (benign {n_benign:,} / phish {n_phish:,}) data_mode={data_mode}")
    print(json.dumps({k: metrics[k] for k in
                      ("precision", "recall", "f1", "roc_auc", "pr_auc", "fpr", "fnr", "confusion", "ece")},
                     indent=2))

    print("\n--- V4 VALIDATION GATES ---")
    gates_ok, gate_rows = run_gates(model, top1m)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\n  saved: {MODEL_PATH}")

    payload = {
        "model": "url_xgb_v4.pkl",
        "schema": "v4",
        "split": "domain-grouped",
        "data_mode": data_mode,
        "n_rows": int(len(frame)),
        "n_benign": n_benign,
        "n_phishing": n_phish,
        "leakage_audit": leakage,
        "gates": gate_rows,
        "gates_pass": bool(gates_ok),
        **metrics,
    }
    METRICS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"  metrics: {METRICS_PATH}")
    print("=== DONE ===")
    return 0 if gates_ok and leakage["overlap_domains"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
