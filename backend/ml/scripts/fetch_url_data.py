"""fetch_url_data.py — Step 1 of the URL v4 retrain pipeline.

Downloads and consolidates large-scale, real-world URL datasets (>= 100k rows)
into a single raw CSV consumed by preprocess_url_v4.py.

Sources (all real, no synthetic rows):
  Malicious:
    1. URLhaus abuse.ch bulk CSV (recent)   — malware-distribution URLs.
       https://urlhaus.abuse.ch/downloads/csv_recent/
    2. mitchellkrogza/Phishing.Database ACTIVE feed — live phishing URLs
       (GitHub raw, ~780k URLs, includes the hard platform-hosted cases).
  Benign:
    3. Cisco Umbrella top-1M list — the SAME whitelist the runtime reputation
       service uses (ml/data/url_whitelist/top1m.txt). The committed file is
       preferred; the umbrella-static S3 zip is downloaded only as a fallback.
  Optional (mixed, adds hard benign+phishing pairs):
    4. PhiUSIIL Phishing URL Dataset (UCI, ~370k URLs). ~230 MB download;
       enable with --with-phiusiil when bandwidth allows.

Output: ml/data/url_datasets/url_v4_raw.csv with columns
    url (str), label (int: 1=malicious, 0=benign), source (str: provenance,
    used by train_url_v4.py for source-aware splitting).

Run from the backend directory:
    uv run python ml/scripts/fetch_url_data.py
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import random
import sys
import time
import zipfile
from pathlib import Path
from typing import Iterator

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Paths — everything is anchored to the backend directory so the script works
# from any CWD (mirrors ml/scripts/train_url_v3.py).
# ---------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_DIR / "ml" / "data" / "url_datasets"
CACHE_DIR = BACKEND_DIR / "ml" / "data" / "cache"
TOP1M_PATH = BACKEND_DIR / "ml" / "data" / "url_whitelist" / "top1m.txt"
RAW_CSV_PATH = DATA_DIR / "url_v4_raw.csv"

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
PHISHING_DB_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
    "master/phishing-links-ACTIVE.txt"
)
UMBRELLA_TOP1M_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
PHIUSIIL_URL = (
    "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
)

URLHAUS_CACHE = CACHE_DIR / "urlhaus_csv_recent.csv"
PHISHING_DB_CACHE = CACHE_DIR / "phishing_feed_active.txt"
UMBRELLA_CACHE = CACHE_DIR / "umbrella_top1m.csv"
PHIUSIIL_CACHE = CACHE_DIR / "phiusiil.zip"

SEED = 42
REQUEST_TIMEOUT_SECS = 180
USER_AGENT = "cyberguard-v4-training/1.0 (malicious-URL-detection research)"

# ---------------------------------------------------------------------------
# Benign tracking-parameter augmentation (v3 lesson, kept for v4).
#
# Bare top-1M homepages alone teach the model "reputable domain => benign",
# but real marketing-email links are long: tracking blobs on reputable hosts.
# v2's flagship FP (medium.com/?source=email-... digest links scored ~0.76)
# is only preventable if the training data contains benign long-tracking URLs
# on real top-1M domains. A share of benign domains therefore gets realistic
# tracking parameters composed onto realistic paths (templates ported from
# ml/scripts/train_url_v3.py).
# ---------------------------------------------------------------------------
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
]
TRACKING_WORDS = ["digest", "newsletter", "weekly", "daily", "promo", "reader"]
TRACK_PATHS = [
    "", "/", "/",  # bare-domain links dominate real marketing email
    "/@{user}", "/p/{id}", "/post/{id}", "/story/{id}", "/watch", "/login",
    "/pricing", "/blog/{id}", "/en/articles/{n}", "/newsletter/{word}-{n}",
]
BENIGN_FRACTION_WITH_TRACKING = 0.30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fetch_url_data")


# ---------------------------------------------------------------------------
# HTTP helpers — retries with exponential backoff, streaming for large files
# ---------------------------------------------------------------------------

def make_session() -> requests.Session:
    """Session with retry/backoff on connection errors, 429 and 5xx."""
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=2,  # 1s, 2s, 4s, 8s, 16s
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def fetch_text(url: str, session: requests.Session, cache: Path | None = None) -> str | None:
    """GET a text resource with retries; returns None on total failure.

    When `cache` is given and exists, the cached copy is served instead of
    re-downloading (download-once, reuse-across-runs semantics like v3).
    """
    if cache is not None and cache.exists() and cache.stat().st_size > 0:
        log.info("  cache hit: %s (%.1f MB)", cache.name, cache.stat().st_size / 1e6)
        return cache.read_text(encoding="utf-8", errors="replace")
    log.info("  downloading: %s", url)
    try:
        with session.get(url, timeout=REQUEST_TIMEOUT_SECS, stream=True) as resp:
            resp.raise_for_status()
            chunks: list[bytes] = []
            for chunk in resp.iter_content(chunk_size=1 << 20):
                chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        if cache is not None:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(text, encoding="utf-8")
        log.info("  downloaded %.1f MB", len(text) / 1e6)
        return text
    except requests.RequestException as exc:
        log.error("  download failed after retries: %s (%s)", url, exc)
        return None


def fetch_bytes(url: str, session: requests.Session, cache: Path) -> bytes | None:
    """GET a binary resource (zip) with retries; None on total failure."""
    if cache.exists() and cache.stat().st_size > 0:
        log.info("  cache hit: %s (%.1f MB)", cache.name, cache.stat().st_size / 1e6)
        return cache.read_bytes()
    log.info("  downloading: %s", url)
    try:
        with session.get(url, timeout=REQUEST_TIMEOUT_SECS, stream=True) as resp:
            resp.raise_for_status()
            chunks: list[bytes] = []
            done = 0
            for chunk in resp.iter_content(chunk_size=1 << 20):
                chunks.append(chunk)
                done += len(chunk)
                if done % (50 << 20) < (1 << 20):
                    log.info("    ... %.0f MB", done / 1e6)
        blob = b"".join(chunks)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(blob)
        log.info("  downloaded %.1f MB", len(blob) / 1e6)
        return blob
    except requests.RequestException as exc:
        log.error("  download failed after retries: %s (%s)", url, exc)
        return None


# ---------------------------------------------------------------------------
# Source 1: URLhaus (malware-distribution URLs) — label 1
# ---------------------------------------------------------------------------

def fetch_urlhaus(session: requests.Session, cap: int) -> list[str]:
    """Parse the URLhaus bulk CSV (comment-prepended header, quoted fields)."""
    text = fetch_text(URLHAUS_CSV_URL, session, URLHAUS_CACHE)
    if text is None:
        return []
    urls: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        # URLhaus CSVs start with comment lines; the first non-comment row is
        # the header: id, dateadded, url, url_status, threat, tags, ...
        if not row or row[0].startswith("#"):
            continue
        if row[0].strip().lower() == "id":
            continue
        if len(row) < 3:
            continue
        url = row[2].strip()
        if url.startswith(("http://", "https://")):
            urls.append(url)
            if len(urls) >= cap:
                break
    log.info("  urlhaus: %s malicious URLs", f"{len(urls):,}")
    return urls


# ---------------------------------------------------------------------------
# Source 2: Phishing.Database ACTIVE feed (live phishing URLs) — label 1
# ---------------------------------------------------------------------------

def fetch_phishing_database(session: requests.Session, cap: int) -> list[str]:
    text = fetch_text(PHISHING_DB_URL, session, PHISHING_DB_CACHE)
    if text is None:
        return []
    urls: list[str] = []
    for line in text.splitlines():
        url = line.strip()
        if url.startswith(("http://", "https://", "ftp://")):
            urls.append(url)
            if len(urls) >= cap:
                break
    log.info("  phishing.database: %s malicious URLs", f"{len(urls):,}")
    return urls


# ---------------------------------------------------------------------------
# Source 3: Umbrella top-1M benign domains — label 0
# ---------------------------------------------------------------------------

def load_top1m_domains(session: requests.Session) -> list[str]:
    """Registrable domains from the runtime whitelist; S3 zip as fallback.

    The committed ml/data/url_whitelist/top1m.txt is the exact set served by
    app/core/url_reputation.py at inference time — preferring it keeps the
    `is_top_1m` feature consistent between training and production.
    """
    if TOP1M_PATH.exists():
        domains = [line.strip().lower() for line in TOP1M_PATH.read_text(
            encoding="utf-8", errors="replace").splitlines() if line.strip()]
        log.info("  top-1M whitelist (committed): %s domains", f"{len(domains):,}")
        return domains
    log.info("  committed top1m.txt missing — downloading Umbrella top-1M fallback")
    blob = fetch_bytes(UMBRELLA_TOP1M_URL, session, UMBRELLA_CACHE)
    if blob is None:
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            name = next(n for n in zf.namelist() if n.endswith(".csv"))
            with zf.open(name) as fh:
                domains = [
                    row[1].strip().lower()
                    for row in csv.reader(io.TextIOWrapper(fh, encoding="utf-8"))
                    if len(row) >= 2 and row[1].strip()
                ]
        log.info("  top-1M whitelist (downloaded): %s domains", f"{len(domains):,}")
        return domains
    except (zipfile.BadZipFile, StopIteration) as exc:
        log.error("  failed to parse Umbrella zip: %s", exc)
        return []


def build_benign_from_top1m(domains: list[str], cap: int, rng: random.Random) -> list[str]:
    """Top-1M domains -> benign URLs; a share carries real tracking params.

    The tracking-augmented rows are still benign BY CONSTRUCTION: the host is
    a real top-1M domain and the query parameters are standard marketing
    parameters (utm_*, fbclid, gclid, mc_cid, ...) on ordinary content paths.
    """
    sampled = rng.sample(domains, min(cap, len(domains)))
    urls: list[str] = []
    n_augmented = 0
    for domain in sampled:
        scheme = "http" if rng.random() < 0.08 else "https"
        if rng.random() < BENIGN_FRACTION_WITH_TRACKING:
            template = rng.choice(TRACKING_TEMPLATES)
            query = template.format(
                hex="".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(8, 16))),
                alnum="".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                              for _ in range(rng.randint(6, 24))),
                word=rng.choice(TRACKING_WORDS),
                n=rng.randint(10**9, 10**12),
            )
            path = rng.choice(TRACK_PATHS)
            path = (path
                    .replace("{id}", "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                                             for _ in range(rng.randint(6, 20))))
                    .replace("{user}", "".join(rng.choice("abcdefghijklmnopqrstuvwxyz")
                                               for _ in range(rng.randint(4, 12))))
                    .replace("{n}", str(rng.randint(1000, 999999999)))
                    .replace("{word}", rng.choice(TRACKING_WORDS)))
            urls.append(f"{scheme}://{domain}{path}{query}")
            n_augmented += 1
        else:
            urls.append(f"{scheme}://{domain}/")
    log.info("  umbrella top-1M: %s benign URLs (%s with tracking-param augmentation)",
             f"{len(urls):,}", f"{n_augmented:,}")
    return urls


# ---------------------------------------------------------------------------
# Source 4 (optional): PhiUSIIL (UCI) — mixed real benign + phishing URLs
# ---------------------------------------------------------------------------

PHIUSIIL_URL_COLUMN = "URL"
# PhiUSIIL label semantics (per the UCI dataset page): 0 = legitimate, 1 = phishing.
PHIUSIIL_LABEL_COLUMN = "label"
PHIUSIIL_MAX_ROWS = 60_000  # keep runtime bounded; sampled evenly across classes


def fetch_phiusiil(session: requests.Session, cap: int, rng: random.Random) -> list[tuple[str, int]]:
    """Download + parse PhiUSIIL; returns balanced (url, label) rows.

    Any failure (network, size, schema) is non-fatal — the pipeline degrades
    to the always-available URLhaus / Phishing.Database / Umbrella trio.
    """
    blob = fetch_bytes(PHIUSIIL_URL, session, PHIUSIIL_CACHE)
    if blob is None:
        return []
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            name = next(
                n for n in zf.namelist()
                if n.endswith(".csv") and "URL" in n and "Image" not in n
            )
            log.info("  phiusiil: reading %s from zip ...", name)
            frame = pd.read_csv(
                zf.open(name),
                usecols=[PHIUSIIL_URL_COLUMN, PHIUSIIL_LABEL_COLUMN],
                on_bad_lines="skip",
            )
    except (zipfile.BadZipFile, StopIteration, ValueError, KeyError) as exc:
        log.error("  failed to parse PhiUSIIL zip: %s — skipping this source", exc)
        return []

    frame = frame.dropna(subset=[PHIUSIIL_URL_COLUMN])
    frame = frame[
        frame[PHIUSIIL_URL_COLUMN].astype(str).str.startswith(("http://", "https://"))
    ]
    # Map PhiUSIIL labels to ours: 1=malicious, 0=benign (semantics match, so
    # the column passes through; the explicit mapping documents the contract).
    frame = frame.rename(
        columns={PHIUSIIL_URL_COLUMN: "url", PHIUSIIL_LABEL_COLUMN: "label"})
    per_class = cap // 2
    rows: list[tuple[str, int]] = []
    for label in (0, 1):
        subset = frame[frame["label"] == label]
        if subset.empty:
            continue
        take = subset.sample(n=min(per_class, len(subset)), random_state=rng.randint(0, 2**31))
        rows.extend((str(u), int(l)) for u, l in zip(take["url"], take["label"]))
    log.info("  phiusiil: %s rows (benign %s / malicious %s)", f"{len(rows):,}",
             f"{sum(1 for _, l in rows if l == 0):,}", f"{sum(1 for _, l in rows if l == 1):,}")
    return rows


# ---------------------------------------------------------------------------
# Consolidation
# ---------------------------------------------------------------------------

def consolidate(
    benign_urls: Iterator[tuple[str, int]],
    malicious_urls: Iterator[tuple[str, int]],
    mixed_rows: list[tuple[str, int]],
    benign_cap: int,
    malicious_cap: int,
    rng: random.Random,
) -> pd.DataFrame:
    """Dedup, resolve cross-source collisions (URL in both feeds -> malicious:
    a compromised benign host is kept on the safe side), cap per class, shuffle."""
    benign: dict[str, tuple[str, int]] = {}
    malicious: dict[str, tuple[str, int]] = {}

    for url, label in benign_urls:
        if len(benign) >= benign_cap:
            break
        benign.setdefault(url, (url, label))
    for url, label in malicious_urls:
        if len(malicious) >= malicious_cap:
            break
        malicious.setdefault(url, (url, label))

    for url in list(benign):  # collisions: benign loses
        if url in malicious:
            del benign[url]

    rows: list[tuple[str, int]] = list(benign.values()) + list(malicious.values()) + mixed_rows
    frame = pd.DataFrame(rows, columns=["url", "label"])
    frame = frame.drop_duplicates(subset="url").sample(frac=1.0, random_state=SEED)
    frame = frame.reset_index(drop=True)
    log.info(
        "  consolidated: %s rows (benign %s / malicious %s)",
        f"{len(frame):,}",
        f"{int((frame['label'] == 0).sum()):,}",
        f"{int((frame['label'] == 1).sum()):,}",
    )
    return frame


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch raw URL datasets for v4 training")
    parser.add_argument("--benign-cap", type=int, default=60_000,
                        help="Max benign rows (default: 60000)")
    parser.add_argument("--malicious-cap", type=int, default=60_000,
                        help="Max malicious rows (default: 60000)")
    parser.add_argument("--with-phiusiil", action="store_true",
                        help="Also download PhiUSIIL from UCI (~230 MB, optional)")
    parser.add_argument("--out", type=Path, default=RAW_CSV_PATH,
                        help="Output CSV path")
    args = parser.parse_args()

    rng = random.Random(SEED)
    session = make_session()
    started = time.monotonic()
    log.info("=== fetch_url_data: target >= %s rows (benign cap %s / malicious cap %s) ===",
             f"{args.benign_cap + args.malicious_cap:,}",
             f"{args.benign_cap:,}", f"{args.malicious_cap:,}")

    # Malicious: URLhaus first, topped up with the Phishing.Database feed.
    urlhaus = fetch_urlhaus(session, args.malicious_cap)
    remaining = max(0, args.malicious_cap - len(urlhaus))
    phishing_db = fetch_phishing_database(session, remaining) if remaining else []
    malicious = [(u, 1) for u in urlhaus + phishing_db]

    # Benign: Umbrella top-1M homepage URLs.
    domains = load_top1m_domains(session)
    if not domains:
        log.error("No benign source available — aborting (refusing to train on "
                  "malicious-only data)")
        return 1
    benign = [(u, 0) for u in build_benign_from_top1m(domains, args.benign_cap, rng)]

    # Optional mixed source (real benign + phishing pairs from PhiUSIIL).
    mixed: list[tuple[str, int]] = []
    if args.with_phiusiil:
        mixed = fetch_phiusiil(session, PHIUSIIL_MAX_ROWS, rng)

    if not malicious:
        log.error("No malicious source available — aborting")
        return 1

    frame = consolidate(
        iter(benign), iter(malicious), mixed,
        benign_cap=args.benign_cap, malicious_cap=args.malicious_cap, rng=rng,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.out, index=False)
    log.info("=== wrote %s rows -> %s (%.1fs) ===",
             f"{len(frame):,}", args.out, time.monotonic() - started)
    return 0


if __name__ == "__main__":
    sys.exit(main())
