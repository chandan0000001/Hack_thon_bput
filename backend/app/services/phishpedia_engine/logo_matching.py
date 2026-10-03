"""Siamese logo matching against the reference brand list (Phishpedia subset).

Upstream `logo_matching.py` computes a mean-embedding per brand over its
reference logo crops and matches a target crop by cosine similarity inside a
specificity-thresholded target domain. The minimal equivalent here:

  * load_domain_map() — Phishpedia's `domain_map.pkl`: {brand: [domains]},
    saved by the upstream prepare step; ALSO accepts the {brand: {"domains":
    [...], "embedding": [floats]}} shape our prepare script writes.
  * match_logo() — cosine similarity between the crop embedding and each
    brand's reference embedding; returns (brand, legitimate_domain,
    confidence) for the best match above threshold.

The reference artifacts are NOT committed; see README.md.
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any

logger = logging.getLogger("cyberguard.phishpedia")

# Phishpedia operates with per-brand specificity thresholds around 0.80-0.85.
DEFAULT_MATCH_THRESHOLD = 0.82


def load_domain_map(path: Path) -> dict[str, dict[str, Any]]:
    """domain_map.pkl -> {brand: {"domains": [...], "embedding": [float]|None}}.

    Supports the upstream pickle format ({brand: [domains]}) and the enriched
    format with precomputed reference embeddings.
    """
    import pickle

    with path.open("rb") as fh:
        raw = pickle.load(fh)
    mapping: dict[str, dict[str, Any]] = {}
    for brand, value in raw.items():
        if isinstance(value, dict):
            mapping[str(brand)] = {
                "domains": [str(d).lower() for d in value.get("domains", [])],
                "embedding": value.get("embedding"),
            }
        else:
            mapping[str(brand)] = {
                "domains": [str(d).lower() for d in (value or [])],
                "embedding": None,
            }
    return mapping


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def match_logo(
    crop_embedding,
    domain_map: dict[str, dict[str, Any]],
    threshold: float = DEFAULT_MATCH_THRESHOLD,
) -> dict | None:
    """Embedding -> best brand above threshold.

    Returns {brand, legitimate_domain, brand_similarity} or None. When a brand
    maps to several domains (multi-brand pages) the first registered domain is
    the legitimate one — Phishpedia's target-domain convention.
    """
    if crop_embedding is None or not domain_map:
        return None
    vec = crop_embedding.flatten().tolist() if hasattr(crop_embedding, "flatten") else list(crop_embedding)

    best: dict | None = None
    for brand, spec in domain_map.items():
        ref = spec.get("embedding")
        similarity = _cosine(vec, ref) if ref is not None else 0.0
        if similarity >= threshold and (best is None or similarity > best["brand_similarity"]):
            domains = spec.get("domains") or []
            best = {
                "brand": brand,
                "legitimate_domain": domains[0] if domains else None,
                "brand_similarity": round(float(similarity), 4),
            }
    return best
