"""preprocess_url_v4.py — Step 2 of the URL v4 retrain pipeline.

Reads the consolidated raw dataset (ml/data/url_datasets/url_v4_raw.csv,
produced by fetch_url_data.py) and maps every URL to the EXACT 19-feature
schema used by the production v3 extractor.

FEATURE LOCK: the extractor is imported from backend/ml/url_features_v3.py —
the same module the runtime inference path uses
(app/services/ml_inference.py:extract_url_features -> extract_url_features_v3),
so training-time features are byte-identical to serving-time features. This
script MUST NOT reimplement or extend the feature set.

The reputation feature `is_top_1m` depends on the Umbrella top-1M set. To keep
it identical to production, the set is loaded through
app.core.url_reputation.top1m_domain_set() (the same loader the runtime uses,
including its always-recognized high-reputation domains).

Output: ml/data/url_datasets/url_v4_processed.csv with columns
    <19 feature columns in FEATURE_COLUMNS_V3 order>, source (provenance),
    label (1=malicious, 0=benign).
All feature values are coerced to finite floats; rows with NaN/inf features or
unparseable URLs are dropped (never imputed — every feature is deterministic
from the URL itself).

Run from the backend directory:
    uv run python ml/scripts/preprocess_url_v4.py
"""

from __future__ import annotations

import argparse
import logging
import math
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_DIR))  # allow `ml.` and `app.` imports from anywhere

from ml.url_features_v3 import FEATURE_COLUMNS_V3, extract_url_features_v3  # noqa: E402

DATA_DIR = BACKEND_DIR / "ml" / "data" / "url_datasets"
RAW_CSV_PATH = DATA_DIR / "url_v4_raw.csv"
PROCESSED_CSV_PATH = DATA_DIR / "url_v4_processed.csv"

PROGRESS_EVERY = 25_000  # rows between progress log lines

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("preprocess_url_v4")


def load_top1m_set() -> set[str]:
    """Load the reputation set exactly the way production does.

    app.core.url_reputation imports cleanly outside the FastAPI app (its
    module-level dependencies are logging/re/pathlib only), so using its
    public accessor guarantees the training-time `is_top_1m` flag matches
    inference — including the small always-recognized high-reputation
    domain additions the service applies on top of the whitelist file.
    """
    try:
        from app.core.url_reputation import top1m_domain_set

        top1m = top1m_domain_set()
        log.info("reputation set loaded via app.core.url_reputation: %s domains",
                 f"{len(top1m):,}")
        return top1m
    except Exception as exc:  # pragma: no cover — offline/standalone fallback
        log.warning("app.core.url_reputation unavailable (%s) — loading top1m.txt "
                    "directly (ccTLD registrable-domain resolution degrades to "
                    "last-two-labels)", exc)
        top1m_path = BACKEND_DIR / "ml" / "data" / "url_whitelist" / "top1m.txt"
        domains: set[str] = set()
        if top1m_path.exists():
            for line in top1m_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    domains.add(line.strip().lower())
        log.info("reputation set loaded from file fallback: %s domains", f"{len(domains):,}")
        return domains


def extract_row(url: str, top1m: set[str]) -> list[float] | None:
    """One URL -> 19 floats in FEATURE_COLUMNS_V3 order, or None if unusable."""
    try:
        features = extract_url_features_v3(url, top1m)
    except Exception:  # malformed URL the extractor cannot normalize
        return None
    vector = [float(features[column]) for column in FEATURE_COLUMNS_V3]
    if not all(math.isfinite(value) for value in vector):
        return None
    return vector


def preprocess(raw_path: Path, out_path: Path) -> pd.DataFrame:
    """Raw CSV -> processed 19-feature CSV. Returns the processed frame."""
    frame = pd.read_csv(raw_path)
    required = {"url", "label"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"raw CSV missing required columns: {sorted(missing)}")
    # `source` is optional provenance written by fetch_url_data.py; used by
    # train_url_v4.py for source-aware splitting.
    has_source = "source" in frame.columns
    log.info("raw dataset: %s rows (%s)", f"{len(frame):,}", raw_path.name)

    top1m = load_top1m_set()

    rows: list[list[float]] = []
    labels: list[int] = []
    sources: list[str] = []
    started = time.monotonic()
    for i, record in enumerate(frame.itertuples(index=False), start=1):
        vector = extract_row(str(record.url), top1m)
        if vector is None:
            continue
        rows.append(vector)
        labels.append(int(record.label))
        sources.append(str(getattr(record, "source", "unknown")))
        if i % PROGRESS_EVERY == 0:
            rate = i / max(time.monotonic() - started, 1e-9)
            log.info("  extracted %s / %s URLs (%.0f rows/s)", f"{i:,}",
                     f"{len(frame):,}", rate)

    processed = pd.DataFrame(rows, columns=FEATURE_COLUMNS_V3)
    processed["label"] = labels
    if has_source:
        processed["source"] = sources

    # Sanity guards: exact feature schema, all-numeric, finite.
    assert list(processed.columns[:len(FEATURE_COLUMNS_V3)]) == FEATURE_COLUMNS_V3, \
        "feature column order drifted from FEATURE_COLUMNS_V3 — feature lock violated"
    non_numeric = [
        column for column in FEATURE_COLUMNS_V3
        if not np.issubdtype(processed[column].dtype, np.number)
    ]
    if non_numeric:
        raise ValueError(f"non-numeric feature columns produced: {non_numeric}")

    processed = processed.sample(frac=1.0, random_state=42).reset_index(drop=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    processed.to_csv(out_path, index=False)

    dropped = len(frame) - len(processed)
    log.info(
        "processed dataset: %s rows (dropped %s unparseable) — benign %s / malicious %s",
        f"{len(processed):,}", f"{dropped:,}",
        f"{int((processed['label'] == 0).sum()):,}",
        f"{int((processed['label'] == 1).sum()):,}",
    )
    log.info("wrote %s", out_path)
    return processed


def main() -> int:
    parser = argparse.ArgumentParser(description="Map raw URLs to the 19-feature v3/v4 schema")
    parser.add_argument("--raw", type=Path, default=RAW_CSV_PATH, help="Raw CSV input")
    parser.add_argument("--out", type=Path, default=PROCESSED_CSV_PATH, help="Processed CSV output")
    args = parser.parse_args()

    if not args.raw.exists():
        log.error("raw dataset not found: %s — run fetch_url_data.py first", args.raw)
        return 1
    preprocess(args.raw, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
