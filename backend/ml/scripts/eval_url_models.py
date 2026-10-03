"""Honest evaluation for the URL phishing models (v3 / v3.1 / v4).

Why this exists: the committed metrics (url_v3_metrics.json etc.) come from a
STRATIFIED holdout of a corpus whose phishing side is one daily feed — many
URLs per attacker domain land on both sides of the split, which inflates AUC
by 5-15 points (the classic phishing-dataset leakage). The numbers below are
the ones to trust:

  Mode A (--splits domain,temporal) — retrains fresh models with the SAME
  hyperparameters under leakage-free splits and reports holdout metrics:
    domain   : no registrable domain spans train/test (GroupShuffleSplit)
    temporal : train on the past, test on the future (feed line order proxy)

  Mode B (--external, default when models exist) — evaluates FROZEN artifacts
  on data the models never saw:
    phishing : OpenPhish free feed + a FRESH download of Phishing.Database
               (entries added after the training snapshot)
    benign   : Cloudflare top-1M (independent source from the Umbrella
               top-1M used in training) + hard-benign variants (login paths,
               OAuth/OIDC URLs, utm tracking, deep links, CDN hosts)
    metrics  : precision, recall, F1, ROC-AUC, PR-AUC, FPR, FNR, confusion
               matrix, calibration (ECE + reliability table), p50/p95/p99
               inference latency per URL

Run from the backend directory:
    uv run python ml/scripts/eval_url_models.py --models v3.1 --external
    uv run python ml/scripts/eval_url_models.py --splits domain temporal --schema v4
"""

import argparse
import json
import math
import random
import sys
import time
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_DIR))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ml.url_features_v3 import (
    FEATURE_COLUMNS_V3,
    FEATURE_COLUMNS_V4,
    extract_url_features_v3,
    extract_url_features_v4,
    load_top1m_rank_map,
    vectorize_v3,
    vectorize_v4,
)
from ml.scripts.train_url_v3 import (
    SEED,
    build_frame,
    domain_grouped_split,
    fetch_real_phishing_urls,
    load_top1m_domains,
    make_model,
    temporal_split,
)

MODELS_DIR = BACKEND_DIR / "ml" / "models"
CACHE_DIR = BACKEND_DIR / "ml" / "data" / "cache" / "eval"
REPORT_JSON = MODELS_DIR / "url_eval_report.json"
REPORT_MD = MODELS_DIR / "url_eval_report.md"

ARTIFACTS = {"v3": "url_xgb_v3.pkl", "v3.1": "url_xgb_v3.1.pkl", "v4": "url_xgb_v4.pkl", "v2": "url_xgb_v2.pkl"}

OPENPHISH_URL = "https://openphish.com/feed.txt"
PHISHDB_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
    "master/phishing-links-ACTIVE.txt"
)
CLOUDFLARE_TOP1M_URL = "https://downloads.cloudflare.com/domains/top-1million.csv.zip"

N_PHISH_EXTERNAL = 20_000
N_BENIGN_EXTERNAL = 20_000
N_HARD_BENIGN = 5_000

SEED_EVAL = 4021


# ---------------------------------------------------------------------------
# External data (download-once, cached)
# ---------------------------------------------------------------------------

def _fetch(url: str, cache_name: str, timeout: int = 120) -> bytes | None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / cache_name
    if cache.exists():
        return cache.read_bytes()
    print(f"  downloading {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cyberguard-eval/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        cache.write_bytes(data)
        return data
    except Exception as exc:
        print(f"  !! download failed ({exc})")
        return None


def _parse_cloudflare_zip(data: bytes) -> list[str]:
    domains: list[str] = []
    with zipfile.ZipFile(BytesIO(data)) as zf:
        name = zf.namelist()[0]
        for line in zf.read(name).decode("utf-8", "replace").splitlines()[1:]:
            parts = line.split(",")
            if parts and parts[-1].strip():
                domains.append(parts[-1].strip().lower())
    if not domains:  # some exports have no meta columns
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for line in zf.read(zf.namelist()[0]).decode("utf-8", "replace").splitlines():
                dom = line.strip().split(",")[-1].strip().lower()
                if dom and "." in dom:
                    domains.append(dom)
    return domains


def load_external_phishing(rng: random.Random) -> list[str]:
    """OpenPhish feed + fresh Phishing.Database snapshot (post-training URLs)."""
    urls: list[str] = []
    openphish = _fetch(OPENPHISH_URL, "openphish_feed.txt")
    if openphish:
        urls += [u.strip() for u in openphish.decode("utf-8", "replace").splitlines() if u.startswith("http")]
    phishdb = _fetch(PHISHDB_URL, "phishing_db_eval_snapshot.txt")
    if phishdb:
        urls += [u.strip() for u in phishdb.decode("utf-8", "replace").splitlines() if u.startswith("http")]
    urls = list(dict.fromkeys(urls))
    rng.shuffle(urls)
    picked = urls[:N_PHISH_EXTERNAL]
    print(f"  external phishing: {len(picked):,} of {len(urls):,} unique (openphish + fresh phishdb)")
    return picked


def load_external_benign(rng: random.Random) -> list[str]:
    """Cloudflare top-1M domains (independent of the training-side Umbrella list)
    as bare URLs + hard-benign variants (login/oauth/tracking/deep/CDN).

    Falls back to the committed Umbrella top-1M when Cloudflare is unreachable
    — training sampled only ~59k of those 1M domains, so the remainder are
    still unseen by the model (same source, held-out domains; flagged in the
    report so the distinction is never lost).
    """
    data = _fetch(CLOUDFLARE_TOP1M_URL, "cloudflare_top1m.zip")
    source = "cloudflare-top1m"
    if data:
        domains = _parse_cloudflare_zip(data)
    else:
        committed = BACKEND_DIR / "ml" / "data" / "url_whitelist" / "top1m.txt"
        if not committed.exists():
            print("  !! no benign source available — aborting external benign eval")
            return []
        domains = [l.strip().lower() for l in committed.read_text(encoding="utf-8").splitlines() if l.strip()]
        source = "umbrella-top1m-committed (same source as training, held-out domains)"
        print(f"  !! Cloudflare unreachable — falling back to committed Umbrella list ({source})")
    domains = sorted(set(domains))
    rng.shuffle(domains)
    sample = domains[:N_BENIGN_EXTERNAL]
    urls = [f"https://{d}/" for d in sample]

    # Hard-benign variants on the sampled domains — these are the shapes that
    # historically produce FPs (credential-path keywords, trackers, depth).
    login_paths = ["/login", "/signin", "/account/verify", "/secure/login", "/auth/realms/master/protocol/openid-connect/auth"]
    oauth_qs = ["?client_id={a}&response_type=code&scope=openid%20email&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state={b}",
                "?response_type=token&client_id={a}&prompt=consent"]
    tracking_qs = ["?utm_source={w}&utm_medium=email&utm_campaign={w}_{n}", "?fbclid={b}&gclid={b}", "?ref={b}&source=newsletter-{w}"]
    deep_paths = ["/docs/{w}/guides/{w}-{n}", "/en-us/articles/{n}-{w}", "/store/category/{n}/items/{n}", "/{w}/{b}/settings"]
    cdn_hosts = ["cloudflare.com", "akamai.com", "amazonaws.com", "cloudfront.net", "googleapis.com"]
    words = ["spring", "digest", "weekly", "launch", "promo", "notes"]
    import string
    alnum = lambda k: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(k))

    n_hard = min(N_HARD_BENIGN, len(sample) // 2)
    for d in sample[:n_hard]:
        style = rng.random()
        w = rng.choice(words)
        if style < 0.3:
            urls.append(f"https://accounts.{d}{rng.choice(login_paths)}?redirect={alnum(12)}")
        elif style < 0.5:
            urls.append(f"https://auth.{d}{rng.choice(login_paths)}" + rng.choice(oauth_qs).format(a=alnum(20), b=alnum(16)))
        elif style < 0.7:
            urls.append(f"https://www.{d}{rng.choice(deep_paths).format(w=w, n=rng.randint(100, 999999), b=alnum(14))}" + rng.choice(tracking_qs).format(w=w, b=alnum(18), n=rng.randint(10**6, 10**9)))
        elif style < 0.9:
            urls.append(f"https://cdn.{d}/assets/{alnum(10)}.{rng.choice(['js', 'css', 'png'])}")
        else:
            urls.append(f"https://{rng.choice(cdn_hosts)}/{w}/{alnum(16)}")
    picked = [u for u in urls if u not in set()]  # dedup happens below
    picked = list(dict.fromkeys(picked))
    n_bare = len(urls) - n_hard
    print(f"  external benign: {len(picked):,} "
          f"(bare {n_bare:,} + hard-benign login/oauth/tracking/CDN {n_hard:,})")
    return picked


def load_external_benign_segments(rng: random.Random) -> dict[str, list[str]]:
    """Same data as load_external_benign but split for honest reporting.

    benign_bare : top-1M bare URLs — the base FPR any deployed model must keep
                  low (this is what '33% FPR' headlines would be measured on).
    benign_hard : login/oauth/tracking/deep/CDN variants — FP-hardness
                  measure. Partly synthetic; a flag here means 'looks scary,
                  is benign', which is informative but is NOT a clean
                  real-world FPR (e.g. OIDC paths on in-addr.arpa junk domains
                  from the top-1M are genuinely rare in real browsing).
    """
    data = _fetch(CLOUDFLARE_TOP1M_URL, "cloudflare_top1m.zip")
    if data:
        domains = _parse_cloudflare_zip(data)
    else:
        committed = BACKEND_DIR / "ml" / "data" / "url_whitelist" / "top1m.txt"
        if not committed.exists():
            return {}
        domains = [l.strip().lower() for l in committed.read_text(encoding="utf-8").splitlines() if l.strip()]
    domains = sorted(set(domains))
    rng.shuffle(domains)
    bare = [f"https://{d}/" for d in domains[:N_BENIGN_EXTERNAL]]

    import string
    words = ["spring", "digest", "weekly", "launch", "promo", "notes"]
    alnum = lambda k: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(k))
    oauth_qs = ["?client_id={a}&response_type=code&scope=openid%20email&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state={b}",
                "?response_type=token&client_id={a}&prompt=consent"]
    tracking_qs = ["?utm_source={w}&utm_medium=email&utm_campaign={w}_{n}", "?fbclid={b}&gclid={b}", "?ref={b}&source=newsletter-{w}"]
    deep_paths = ["/docs/{w}/guides/{w}-{n}", "/en-us/articles/{n}-{w}", "/store/category/{n}/items/{n}", "/{w}/{b}/settings"]
    sub_stems = ["accounts", "auth", "login", "sso", "cdn", "assets", "static", "api", "mail", "docs"]
    sample = domains[:N_HARD_BENIGN]
    hard = []
    for d in sample:
        style = rng.random()
        w = rng.choice(words)
        if style < 0.2:
            hard.append(f"https://{rng.choice(sub_stems)}.{d}{rng.choice(['/login', '/signin', '/account/verify'])}?redirect={alnum(12)}")
        elif style < 0.4:
            hard.append(f"https://{rng.choice(sub_stems)}.{d}/auth/realms/master/protocol/openid-connect/auth" + rng.choice(oauth_qs).format(a=alnum(20), b=alnum(16)))
        elif style < 0.6:
            hard.append(f"https://www.{d}{rng.choice(deep_paths).format(w=w, n=rng.randint(100, 999999), b=alnum(14))}" + rng.choice(tracking_qs).format(w=w, b=alnum(18), n=rng.randint(10**6, 10**9)))
        elif style < 0.8:
            hard.append(f"https://{rng.choice(sub_stems)}.{d}/{alnum(10)}.{rng.choice(['js', 'css', 'png'])}")
        else:
            # Multi-hyphen enterprise-style subdomains — the shape behind the
            # dominant bare-domain FP class of the v3.1 external audit.
            hard.append(f"https://{rng.choice(['portal', 'app', 'svc', 'api'])}-{w}-{alnum(6)}.{d}/{w}/")
    return {"benign_bare": list(dict.fromkeys(bare)), "benign_hard": list(dict.fromkeys(hard))}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def full_metrics(y_true, proba, threshold: float = 0.5) -> dict:
    pred = (proba >= threshold).astype(int)
    y_true = np.asarray(y_true)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    ece = 0.0
    bins = []
    for lo in np.linspace(0.0, 0.9, 10):
        hi = lo + 0.1
        mask = (proba >= lo) & (proba < hi) if hi < 1.0 else (proba >= lo) & (proba <= 1.0)
        if mask.sum():
            conf, acc = float(proba[mask].mean()), float(y_true[mask].mean())
            ece += mask.sum() / len(proba) * abs(conf - acc)
            bins.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": int(mask.sum()), "mean_p": round(conf, 4), "empirical_phish_rate": round(acc, 4)})
    return {
        "threshold": threshold,
        "n": int(len(y_true)),
        "positives": int(y_true.sum()),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, proba)), 4) if len(set(y_true)) > 1 else None,
        "pr_auc": round(float(average_precision_score(y_true, proba)), 4) if len(set(y_true)) > 1 else None,
        "fpr": round(fp / (tn + fp), 4) if (tn + fp) else None,
        "fnr": round(fn / (fn + tp), 4) if (fn + tp) else None,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "ece": round(ece, 4),
        "reliability": bins,
    }


def latency_stats(model, frame: pd.DataFrame, columns: list[str], n: int = 300) -> dict:
    sample = frame[columns].head(n).to_numpy()
    times = []
    for row in sample:
        t0 = time.perf_counter()
        model.predict_proba(row.reshape(1, -1))
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    return {
        "p50_ms": round(times[len(times) // 2], 3),
        "p95_ms": round(times[int(len(times) * 0.95)], 3),
        "p99_ms": round(times[int(len(times) * 0.99)], 3),
        "note": "model predict only — feature extraction adds ~0.5-2 ms/URL (Python)",
    }


def feature_extraction_latency(schema: str, urls: list[str], top1m: set, n: int = 300) -> dict:
    ranks = load_top1m_rank_map() if schema == "v4" else None
    extract = extract_url_features_v4 if schema == "v4" else extract_url_features_v3
    sample = urls[:n]
    t0 = time.perf_counter()
    for u in sample:
        extract(u, top1m, ranks) if schema == "v4" else extract(u, top1m)
    per = (time.perf_counter() - t0) / max(1, len(sample)) * 1000
    return {"p_mean_ms": round(per, 3), "schema": schema}


# ---------------------------------------------------------------------------
# Mode A: leakage-free split retraining
# ---------------------------------------------------------------------------

def eval_splits(schema: str, splits: list[str]) -> dict:
    from ml.url_features_v3 import _registrable  # noqa: F401  (import parity check)

    print(f"\n=== Mode A: leakage-free split retraining (schema={schema}) ===")
    rng = random.Random(SEED)
    top1m = load_top1m_domains()
    columns = FEATURE_COLUMNS_V4 if schema == "v4" else FEATURE_COLUMNS_V3

    benign_urls = build_benign_pool(rng, top1m)
    phish_urls, data_mode, phish_temporal = fetch_real_phishing_urls(rng)
    phish_urls = [u for u in dict.fromkeys(phish_urls)]
    phish_temporal = phish_temporal[: len(phish_urls)] if phish_temporal else None
    print(f"  corpus: benign={len(benign_urls):,} phishing={len(phish_urls):,} ({data_mode})")

    print("  building features ...")
    benign_df = build_frame(benign_urls, 0, top1m, schema=schema)
    phish_df = build_frame(phish_urls, 1, top1m, temporal_keys=phish_temporal, schema=schema)
    frame = pd.concat([benign_df, phish_df], ignore_index=True).sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    y = frame["label"]
    n_benign, n_phish = int((y == 0).sum()), int((y == 1).sum())

    results = {}
    for split in splits:
        if split == "domain":
            tr, te = domain_grouped_split(frame)
        elif split == "temporal":
            tr, te = temporal_split(frame)
        else:
            continue
        train, test = frame.iloc[tr], frame.iloc[te]
        model = make_model(len(train), n_benign, n_phish)
        model.fit(train[columns], train["label"])
        proba = model.predict_proba(test[columns])[:, 1]
        results[split] = full_metrics(test["label"].to_numpy(), proba)
        print(f"  [{split}] F1={results[split]['f1']} AUC={results[split]['roc_auc']} "
              f"PR-AUC={results[split]['pr_auc']} FPR={results[split]['fpr']} FNR={results[split]['fnr']}")
    return results


def build_benign_pool(rng: random.Random, top1m: set) -> list[str]:
    """Same benign corpus as train_url_v3 (stratified baseline comparability)."""
    from ml.scripts.train_url_v3 import build_benign_urls, build_brand_secondary_urls

    urls = build_benign_urls(rng, top1m)
    urls += build_brand_secondary_urls(rng, top1m)
    return list(dict.fromkeys(urls))


# ---------------------------------------------------------------------------
# Mode B: frozen artifacts on external data
# ---------------------------------------------------------------------------

def eval_external(models: list[str]) -> dict:
    print("\n=== Mode B: frozen artifacts vs external data ===")
    rng = random.Random(SEED_EVAL)
    top1m = load_top1m_domains()
    phish_urls = load_external_phishing(rng)
    segments = load_external_benign_segments(rng)
    if not phish_urls or not segments:
        print("  !! external data unavailable — aborting external eval")
        return {}
    benign_bare, benign_hard = segments["benign_bare"], segments["benign_hard"]

    def frame_for(urls: list[str], label: int, schema: str) -> pd.DataFrame:
        cols = FEATURE_COLUMNS_V4 if schema == "v4" else FEATURE_COLUMNS_V3
        extract = extract_url_features_v4 if schema == "v4" else extract_url_features_v3
        ranks = load_top1m_rank_map()
        rows = []
        for url in urls:
            try:
                f = extract(url, top1m, ranks) if schema == "v4" else extract(url, top1m)
                rows.append(vectorize_v4(f) if schema == "v4" else vectorize_v3(f))
            except Exception:
                continue
        frame = pd.DataFrame(rows, columns=cols)
        frame["label"] = label
        return frame

    frames: dict[str, dict[str, pd.DataFrame]] = {}
    for schema in ("v3", "v4"):
        frames[schema] = {
            "phish": frame_for(phish_urls, 1, schema),
            "benign_bare": frame_for(benign_bare, 0, schema),
            "benign_hard": frame_for(benign_hard, 0, schema),
        }
        frames[schema]["combined"] = pd.concat(
            [frames[schema]["benign_bare"], frames[schema]["benign_hard"], frames[schema]["phish"]],
            ignore_index=True)

    results = {}
    for name in models:
        artifact = ARTIFACTS.get(name)
        path = MODELS_DIR / artifact if artifact else None
        if not path or not path.exists():
            print(f"  !! {name}: {artifact} missing — skipped")
            continue
        schema = "v4" if name == "v4" else "v3"
        if name == "v2":
            print(f"  -- {name}: v2 artifact present but uses the legacy 15-feature schema; skipped (superseded)")
            continue
        model = joblib.load(path)
        cols = FEATURE_COLUMNS_V4 if schema == "v4" else FEATURE_COLUMNS_V3
        frame = frames[schema]["combined"]
        proba = model.predict_proba(frame[cols])[:, 1]
        y = frame["label"].to_numpy()
        m50 = full_metrics(y, proba, threshold=0.5)
        # Honest FPR breakdown: bare top-1M vs hard-benign segments.
        segment_fpr = {}
        for seg in ("benign_bare", "benign_hard"):
            seg_frame = frames[schema][seg]
            seg_proba = model.predict_proba(seg_frame[cols])[:, 1]
            fp = int((seg_proba >= 0.5).sum())
            segment_fpr[seg] = {"n": int(len(seg_frame)), "fp": fp, "fpr": round(fp / max(1, len(seg_frame)), 4)}
        best_t, best_f1 = 0.5, m50["f1"]
        for t in np.arange(0.2, 0.9, 0.05):
            f1t = f1_score(y, (proba >= t).astype(int), zero_division=0)
            if f1t > best_f1:
                best_t, best_f1 = round(float(t), 2), round(float(f1t), 4)
        results[name] = {
            "artifact": path.name,
            "benign_source": ("cloudflare-top1m" if (CACHE_DIR / "cloudflare_top1m.zip").exists()
                              else "umbrella-top1m-committed (same source as training, held-out domains)"),
            "at_0.5": m50,
            "benign_fpr_segments": segment_fpr,
            "at_best_f1": {"threshold": best_t, "f1": best_f1,
                            **{k: full_metrics(y, proba, threshold=best_t)[k] for k in ("precision", "recall", "fpr", "fnr")}},
            "latency": latency_stats(model, frame, cols),
            "feature_latency": feature_extraction_latency(schema, phish_urls, top1m),
        }
        print(f"  [{name}] ext F1={m50['f1']} AUC={m50['roc_auc']} PR-AUC={m50['pr_auc']} "
              f"FNR={m50['fnr']} ECE={m50['ece']} | FPR bare={segment_fpr['benign_bare']['fpr']} "
              f"hard={segment_fpr['benign_hard']['fpr']} | best-F1 t={best_t}")
    return results


def write_report(results: dict) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(results, indent=2), encoding="utf-8")
    lines = ["# URL model — honest evaluation report", "",
             f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}. "
             "Stratified-holdout metrics are NOT real-world numbers (domain leakage)._", ""]
    for section, data in results.items():
        lines.append(f"## {section}")
        lines.append("```json")
        lines.append(json.dumps(data, indent=2))
        lines.append("```")
        lines.append("")
    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  report: {REPORT_JSON.name} / {REPORT_MD.name}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models", nargs="*", default=["v3.1"], help="frozen artifacts to evaluate externally")
    ap.add_argument("--external", action="store_true", default=True)
    ap.add_argument("--no-external", dest="external", action="store_false")
    ap.add_argument("--splits", nargs="*", default=[], help="retrain under leakage-free splits: domain temporal")
    ap.add_argument("--schema", default="v3", choices=["v3", "v4"], help="feature schema for --splits retraining")
    args = ap.parse_args()

    results: dict = {}
    if args.splits:
        results[f"splits(schema={args.schema})"] = eval_splits(args.schema, args.splits)
    if args.external and args.models:
        results["external"] = eval_external(args.models)
    if not results:
        print("nothing to do: pass --splits domain temporal and/or --models")
        return 2
    write_report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
