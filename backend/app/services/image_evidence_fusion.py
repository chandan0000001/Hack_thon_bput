"""Deterministic image evidence fusion (Model A + Model B + forensics).

All fusion mathematics for the image/deepfake pipeline lives here —
deepfake_detector.py only orchestrates. The output is a deterministic
function of the inputs: the same evidence always produces the same final
probability, and the LLM explanation layer may NEVER override it.

Fusion priority (fiximage.md section 10):

  A. Strong forensic evidence (ELA splice / metadata) — raises, never lowers
  B. Model agreement           — both ML models point the same way
  C. Model disagreement        — reported as evidence, NOT resolved into a
                                 confident fake/real verdict
  D. Individual model confidence
  E. Missing-model fallback    — Model A + B + forensics -> A + forensics ->
                                 B + forensics -> forensics-only

EXPLICITLY FORBIDDEN and never used here:
    final_probability = (model_a + model_b) / 2
"""

import logging
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.deepfake.fusion")

FUSION_METHOD = "calibrated_evidence_fusion"

# Types in the metadata/forensic indicator list treated as strong manipulation
# evidence independent of the ML models (fiximage.md section 3/9).
STRONG_METADATA_INDICATOR_TYPES = frozenset({"container_mismatch"})

# Confidence constants for get_image_detection_confidence().
_CONFIDENCE_AGREEMENT = 0.85
_CONFIDENCE_AGREEMENT_FORENSICS_ALIGNED = 0.9
_CONFIDENCE_AGREEMENT_FORENSICS_CONTRADICTS = 0.7
_CONFIDENCE_SINGLE_MODEL = 0.6
_CONFIDENCE_SINGLE_MODEL_FORENSICS_ALIGNED = 0.7
_CONFIDENCE_DISAGREEMENT = 0.3
_CONFIDENCE_FORENSICS_ONLY_STRONG = 0.5
_CONFIDENCE_FORENSICS_ONLY_WEAK = 0.25


def _disagreement_threshold() -> float:
    return float(get_settings().DEEPFAKE_MODEL_DISAGREEMENT_THRESHOLD)


def calculate_model_disagreement(
    model_a_probability: float | None,
    model_b_probability: float | None,
) -> float | None:
    """Absolute |A - B| divergence between the two ML detectors.

    None when either model has no probability (unavailable) — disagreement
    is undefined without both signals and must never be inferred.
    """
    if model_a_probability is None or model_b_probability is None:
        return None
    return round(abs(float(model_a_probability) - float(model_b_probability)), 4)


def _has_strong_metadata_evidence(metadata_indicators: list[dict] | None) -> bool:
    return any(
        str(ind.get("type", "")) in STRONG_METADATA_INDICATOR_TYPES
        for ind in (metadata_indicators or [])
    )


def _is_strong_forensic_evidence(
    forensic_probability: float,
    splice_score: float,
    strong_splice_threshold: float,
    metadata_indicators: list[dict] | None,
) -> bool:
    """Priority A: ELA splice, elevated forensic probability, or re-wrap proof."""
    return bool(
        splice_score >= strong_splice_threshold
        or forensic_probability >= 0.5
        or _has_strong_metadata_evidence(metadata_indicators)
    )


def should_run_secondary_model(
    model_a_probability: float | None,
    forensic_probability: float = 0.0,
    splice_score: float = 0.0,
    indicators: list[dict] | None = None,
    strong_splice_threshold: float | None = None,
) -> bool:
    """Confidence gate deciding whether Model B (Sentry) runs for this image.

    Model B is an independent verification signal, NOT a default second pass:

      * disabled by configuration (or ML disabled)      -> never run
      * Model A unavailable                              -> run (fallback path)
      * Model A uncertain (in the low..high band)        -> run
      * Model A confident REAL but forensics disagree
        (strong splice / forensic probability / container mismatch) -> run
      * Model A confident (either direction), forensics not
        contradicting                                    -> skip (spec §8:
        a 0.92 fake or 0.08 real verdict needs no second model)
    """
    settings = get_settings()
    if not settings.DEEPFAKE_SECONDARY_ENABLED or not settings.ML_ENABLED:
        return False

    if model_a_probability is None:
        return True

    low = float(settings.DEEPFAKE_SECONDARY_LOW_CONFIDENCE)
    high = float(settings.DEEPFAKE_SECONDARY_HIGH_CONFIDENCE)
    strong_splice = (
        float(strong_splice_threshold)
        if strong_splice_threshold is not None
        else 4.0
    )

    # Uncertain band: neither confidently real (<= low) nor confidently fake (>= high).
    if low < model_a_probability < high:
        return True

    strong_forensics = _is_strong_forensic_evidence(
        forensic_probability, splice_score, strong_splice, indicators
    )
    if model_a_probability <= low and strong_forensics:
        # Confident real verdict contradicted by independent forensic evidence.
        return True
    return False


def get_image_detection_confidence(
    model_a_probability: float | None,
    model_b_probability: float | None,
    forensic_probability: float,
    splice_score: float,
    strong_splice_threshold: float | None = None,
    metadata_indicators: list[dict] | None = None,
) -> float:
    """Confidence (0-1) in the fused verdict — deterministic, evidence-based."""
    strong_splice = (
        float(strong_splice_threshold) if strong_splice_threshold is not None else 4.0
    )
    strong_forensics = _is_strong_forensic_evidence(
        forensic_probability, splice_score, strong_splice, metadata_indicators
    )
    if model_a_probability is not None and model_b_probability is not None:
        if calculate_model_disagreement(model_a_probability, model_b_probability) <= _disagreement_threshold():
            models_fake = (model_a_probability + model_b_probability) / 2.0 >= 0.5
            forensics_fake = strong_forensics or forensic_probability >= 0.5
            if models_fake == forensics_fake:
                return _CONFIDENCE_AGREEMENT_FORENSICS_ALIGNED
            # Forensics actively oppose the model consensus vs forensics
            # merely silent — silent evidence costs less confidence.
            return (
                _CONFIDENCE_AGREEMENT_FORENSICS_CONTRADICTS
                if strong_forensics
                else _CONFIDENCE_AGREEMENT
            )
        return _CONFIDENCE_DISAGREEMENT
    if model_a_probability is not None or model_b_probability is not None:
        return (
            _CONFIDENCE_SINGLE_MODEL_FORENSICS_ALIGNED
            if strong_forensics
            else _CONFIDENCE_SINGLE_MODEL
        )
    return (
        _CONFIDENCE_FORENSICS_ONLY_STRONG if strong_forensics else _CONFIDENCE_FORENSICS_ONLY_WEAK
    )


def fuse_image_evidence(
    model_a_probability: float | None,
    model_b_probability: float | None = None,
    model_b_available: bool = True,
    forensic_probability: float = 0.0,
    primary_blended_probability: float | None = None,
    splice_score: float = 0.0,
    metadata_indicators: list[dict] | None = None,
    strong_splice_threshold: float | None = None,
) -> dict[str, Any]:
    """Fuse Model A, optional Model B, and ELA/metadata forensics.

    Returns a deterministic evidence dict:
        {
            "probability": float,          # final deterministic score
            "method": "calibrated_evidence_fusion",
            "secondary_invoked": bool,     # Model B actually contributed
            "confidence": float,           # get_image_detection_confidence()
            "agreement": bool | None,      # None when fewer than two models
            "disagreement": float | None,  # |A - B|, None without both models
            "fallback": str,               # which fallback path produced the score
            "rationale": str,              # deterministic explanation for the LLM
        }

    When Model B did not run (gate kept it out, it is disabled, or it is
    unavailable) the score is the EXISTING pipeline output
    (`primary_blended_probability`) passed through unchanged — fusion adds a
    signal, it never rewrites a verdict it had no part in producing.
    """
    strong_splice = (
        float(strong_splice_threshold) if strong_splice_threshold is not None else 4.0
    )
    strong_forensics = _is_strong_forensic_evidence(
        forensic_probability, splice_score, strong_splice, metadata_indicators
    )
    disagreement = calculate_model_disagreement(model_a_probability, model_b_probability)
    b_usable = model_b_probability is not None and model_b_available
    model_b_ran = b_usable

    if not model_b_ran:
        # Priority E: missing-model fallback. Preserve the existing pipeline
        # verdict (Model A + forensics hybrid logic) untouched.
        if model_a_probability is not None:
            fallback = "primary_only"
            rationale = (
                "Secondary detector not invoked; verdict from the primary "
                "MobileNetV3-Small model and ELA/metadata forensics."
            )
        elif b_usable:
            fallback = "secondary_only"
        else:
            fallback = "forensics_only"
            rationale = (
                "Both neural detectors unavailable; verdict from ELA/metadata "
                "forensics heuristics only."
            )
        probability = (
            float(primary_blended_probability)
            if primary_blended_probability is not None
            else float(forensic_probability)
        )
        result = _fusion_result(
            probability=probability,
            secondary_invoked=False,
            confidence=get_image_detection_confidence(
                model_a_probability,
                model_b_probability,
                forensic_probability,
                splice_score,
                strong_splice,
                metadata_indicators,
            ),
            agreement=None,
            disagreement=None,
            fallback=fallback,
            rationale=rationale,
        )
        logger.info(
            "deepfake_fusion_complete fallback=%s probability=%.4f",
            fallback,
            probability,
        )
        return result

    if model_a_probability is None:
        # Priority E: Model B + forensics (Model A unavailable) — must be
        # clearly reported, never silently presented as a normal verdict.
        base = float(model_b_probability)
        probability = max(base, float(forensic_probability)) if strong_forensics else base
        result = _fusion_result(
            probability=probability,
            secondary_invoked=True,
            confidence=get_image_detection_confidence(
                None, model_b_probability, forensic_probability, splice_score,
                strong_splice, metadata_indicators,
            ),
            agreement=None,
            disagreement=None,
            fallback="secondary_only",
            rationale=(
                "Primary model unavailable; verdict from the secondary Sentry "
                "ConvNeXt Small detector "
                + ("raised by strong forensic evidence." if strong_forensics else "and ELA/metadata forensics.")
            ),
        )
        logger.info(
            "deepfake_fusion_complete fallback=secondary_only probability=%.4f", probability
        )
        return result

    # --- Both models available: priority B (agreement) / C (disagreement) ---
    a = float(model_a_probability)
    b = float(model_b_probability)
    agrees = disagreement <= _disagreement_threshold()

    if agrees:
        if a >= 0.5 and b >= 0.5:
            # Agreed FAKE: take the STRONGER fake vote (max, not an average).
            base = max(a, b)
            rationale = (
                f"Both detectors report manipulation (model_a={a:.2f}, "
                f"model_b={b:.2f}); the stronger fake probability is used."
            )
        elif a <= 0.5 and b <= 0.5:
            # Agreed REAL: take the stronger real vote (min) — the most
            # conservative real probability of the two.
            base = min(a, b)
            rationale = (
                f"Both detectors report authenticity (model_a={a:.2f}, "
                f"model_b={b:.2f}); the lower fake probability is used."
            )
        else:
            base = max(a, b)
            rationale = (
                f"Detectors straddle the decision boundary (model_a={a:.2f}, "
                f"model_b={b:.2f}); the higher fake probability is kept."
            )
    else:
        # Priority C: disagreement is evidence, not a verdict. Conservative
        # deterministic resolution — never a confident call from a split.
        if min(a, b) >= 0.5:
            base = min(a, b)
            rationale = (
                f"Detectors disagree in magnitude but both lean fake "
                f"(model_a={a:.2f}, model_b={b:.2f}); the weaker fake "
                "probability is used conservatively."
            )
        elif max(a, b) <= 0.5:
            base = max(a, b)
            rationale = (
                f"Detectors disagree in magnitude but both lean real "
                f"(model_a={a:.2f}, model_b={b:.2f}); the higher fake "
                "probability is used conservatively."
            )
        else:
            base = 0.5
            rationale = (
                f"Strong model disagreement with opposed verdicts "
                f"(model_a={a:.2f}, model_b={b:.2f}); no confident fake or "
                "real call is made without independent forensic support."
            )

    # Priority A: strong forensic evidence raises the verdict, never lowers it.
    if strong_forensics and base < forensic_probability:
        base = float(forensic_probability)
        rationale += (
            f" Strong forensic evidence (splice_score={splice_score:.2f}) "
            "raised the final probability."
        )

    probability = min(max(base, 0.0), 1.0)
    confidence = get_image_detection_confidence(
        a, b, forensic_probability, splice_score, strong_splice, metadata_indicators
    )
    result = _fusion_result(
        probability=probability,
        secondary_invoked=True,
        confidence=confidence,
        agreement=agrees,
        disagreement=disagreement,
        fallback="none",
        rationale=rationale,
    )
    logger.info(
        "deepfake_fusion_complete fallback=none probability=%.4f agreement=%s disagreement=%s",
        probability,
        agrees,
        disagreement,
    )
    return result


def _fusion_result(
    probability: float,
    secondary_invoked: bool,
    confidence: float,
    agreement: bool | None,
    disagreement: float | None,
    fallback: str,
    rationale: str,
) -> dict[str, Any]:
    return {
        "probability": round(min(max(float(probability), 0.0), 1.0), 4),
        "method": FUSION_METHOD,
        "secondary_invoked": secondary_invoked,
        "confidence": round(float(confidence), 4),
        "agreement": agreement,
        "disagreement": disagreement,
        "fallback": fallback,
        "rationale": rationale,
    }
