"""Visual phishing worker — Stage-2 Phishpedia jobs (heavy CV off the API).

The API enqueues `visual_phish_check` with (url, screenshot_b64); this worker
runs the logo detector + Siamese matcher, fuses the visual evidence with the
Stage-1 URL verdict (app/services/evidence_fusion.py) and stores the fused
verdict in Redis with a TTL — the cache is keyed on the REGISTRABLE domain so
repeated navigation to the same attacker domain reuses the verdict instead of
re-running computer vision.

Launch (same pattern as the other workers):
    python -m arq app.workers.visual_worker.WorkerSettings
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Any

from app.core.url_reputation import get_registrable_domain
from app.services.evidence_fusion import fuse_url_evidence
from app.services.ml_inference import score_with_ml
from app.services.url_detector import analyze_url_heuristics
from app.workers.base import WorkerSettings as _BaseWorkerSettings
from app.workers.base import get_worker_logger, log_worker_event

logger = get_worker_logger("cyberguard.visual_worker")

# Fused verdict TTL (seconds). Visual verdicts go stale as attacker pages move.
VISUAL_VERDICT_TTL_SECONDS = 3600


def visual_verdict_cache_key(url: str) -> str:
    return f"visual_verdict:{get_registrable_domain(url)}"


def _decode_screenshot(screenshot_b64: str) -> bytes | None:
    try:
        payload = screenshot_b64.split(",", 1)[-1]  # tolerate data: URLs
        return base64.b64decode(payload, validate=False)
    except (binascii.Error, ValueError):
        return None


async def visual_phish_check_job(ctx: dict[str, Any], url: str, screenshot_b64: str) -> dict[str, Any]:
    """One Stage-2 job: visual evidence + fusion, cached in Redis by domain."""
    redis = ctx.get("redis")
    cache_key = visual_verdict_cache_key(url)
    try:
        if redis is not None:
            cached = await redis.get(cache_key)
            if cached:
                import json

                return json.loads(cached)
    except Exception as exc:  # cache miss on redis trouble is not a failure
        logger.warning("visual verdict cache read failed: %s", exc)

    image_bytes = _decode_screenshot(screenshot_b64 or "")
    visual = None
    if image_bytes:
        from app.services.phishpedia_engine import analyze_screenshot

        visual = analyze_screenshot(url, image_bytes)

    # Stage 1 (fast path — heuristics + XGBoost; policy='url' confidence floor).
    indicators = analyze_url_heuristics(url)
    heuristic_score, hybrid_score, ml_probability = score_with_ml(indicators, policy="url")

    fusion = fuse_url_evidence(
        url_probability=ml_probability,
        url_heuristic_score=heuristic_score,
        **({k: visual[k] for k in (
            "brand_detected", "brand_similarity", "matched_legitimate_domain",
            "domain_brand_consistent", "phishpedia_confidence") if visual and k in visual}
           if visual else {}),
        visual_verdict_available=visual is not None,
    )
    result = {
        "url": url,
        "stage1": {
            "heuristic_score": heuristic_score,
            "hybrid_score": hybrid_score,
            "ml_probability": ml_probability,
            "indicators": [
                {k: i.get(k) for k in ("type", "value", "severity", "probability")}
                for i in indicators
            ],
        },
        "stage2": visual,
        "fusion": fusion,
    }

    try:
        if redis is not None:
            import json

            await redis.setex(cache_key, VISUAL_VERDICT_TTL_SECONDS, json.dumps(result))
    except Exception as exc:
        logger.warning("visual verdict cache write failed: %s", exc)

    log_worker_event(
        logger, logging.INFO, f"visual_phish_check done: {fusion.get('decision')}",
        job_type="visual_phish_check", worker_name="visual-worker",
        url_domain=get_registrable_domain(url),
    )
    return result


async def visual_verdict_cache_get(ctx: dict[str, Any], url: str) -> dict[str, Any] | None:
    """Read a cached fused verdict (used by the polling GET endpoint)."""
    redis = ctx.get("redis")
    if redis is None:
        return None
    try:
        import json

        cached = await redis.get(visual_verdict_cache_key(url))
        return json.loads(cached) if cached else None
    except Exception:
        return None


def _build_functions() -> list[Any]:
    from arq.worker import func

    return [
        func(visual_phish_check_job, name="visual_phish_check"),
        visual_phish_check_job,
    ]


class WorkerSettings(_BaseWorkerSettings):
    """Worker settings for Stage-2 visual phishing checks.

    Inherits redis/queue/timeouts/startup from the base settings; arq injects
    ctx['redis'] into every job, which this worker uses for the domain-keyed
    TTL verdict cache.
    """

    functions: list[Any] = _build_functions()
