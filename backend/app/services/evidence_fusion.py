"""Evidence fusion for the cascaded URL pipeline (Stage 1 + Stage 2).

Stage 1 (lexical): XGBoost URL model + URL heuristics.
Stage 2 (visual):  Phishpedia logo/brand evidence, run only for Stage-1
suspicious URLs.

This module deliberately does NOT average scores. Stage 2 answers a different
question than Stage 1 (is this a visual impersonation of a known brand?) and
its signals are categorical (brand detected / brand-domain mismatch), so a
linear blend would dilute both. Instead the policy below keeps every evidence
field separate and combines them with explicit rules:

  Policy inputs (all optional except the Stage-1 fields):
    url_probability            — Stage-1 XGBoost probability [0,1]
    url_heuristic_score        — heuristic indicator score [0,100]
    brand_detected             — visual brand name from the screenshot
    brand_similarity           — Siamese cosine similarity [0,1]
    matched_legitimate_domain  — official domain registered for that brand
    domain_brand_consistent    — page domain belongs to the brand (True/False/None)
    phishpedia_confidence      — logo detector score [0,1]

  Decisions:
    SAFE    — Stage-1 low risk; (Stage 2 is not even run on these)
    WARN    — suspicious but benign visual evidence (e.g. brand matches the
              page's own domain: it IS the real site, model misfired)
    REVIEW  — conflicting evidence: model suspicious but no brand / no verdict
    BLOCK   — Stage-1 high risk AND visual impersonation (brand detected on a
              domain that does not belong to that brand)

The fusion is monotone in the dangerous direction: adding Stage-2 evidence can
raise WARN/REVIEW to BLOCK, and consistent-brand evidence can lower a weak
Stage-1 signal to WARN, but nothing ever hides the raw evidence — the full
dict is returned alongside the decision for the alert payload and the UI.
"""

from __future__ import annotations

from typing import Any

DECISION_SAFE = "safe"
DECISION_WARN = "warn"
DECISION_REVIEW = "review"
DECISION_BLOCK = "block"

# Stage-1 bands (validated on the external eval in ml/scripts/eval_url_models.py).
STAGE1_SAFE_MAX = 0.50        # XGBoost probability below this -> SAFE, no Stage 2
STAGE1_SUSPICIOUS_MIN = 0.60  # at or above -> SUSPICIOUS -> trigger Stage 2
STAGE1_HIGH_MIN = 0.85        # at or above -> high-confidence Stage-1 phish
# Visual evidence thresholds (Phishpedia specificity regime).
VISUAL_IMPERSONATION_MIN = 0.80  # brand_similarity at which mismatch = impersonation

FUSION_FIELDS = (
    "url_probability",
    "url_heuristic_score",
    "brand_detected",
    "brand_similarity",
    "matched_legitimate_domain",
    "domain_brand_consistent",
    "phishpedia_confidence",
)


def stage2_required(url_probability: float | None) -> bool:
    """Cascade gate: run the visual engine only for suspicious Stage-1 verdicts."""
    if url_probability is None:
        return False
    return url_probability >= STAGE1_SUSPICIOUS_MIN


def fuse_url_evidence(
    *,
    url_probability: float | None = None,
    url_heuristic_score: int | None = None,
    brand_detected: str | None = None,
    brand_similarity: float | None = None,
    matched_legitimate_domain: str | None = None,
    domain_brand_consistent: bool | None = None,
    phishpedia_confidence: float | None = None,
    visual_verdict_available: bool = False,
) -> dict[str, Any]:
    """Combine Stage-1 and Stage-2 evidence under the explicit policy.

    Returns {decision, risk_score, reasons[], evidence{...}} — the evidence
    block echoes every input so the alert/UI can show WHY, not just WHAT.
    """
    evidence = {
        "url_probability": url_probability,
        "url_heuristic_score": url_heuristic_score,
        "brand_detected": brand_detected,
        "brand_similarity": brand_similarity,
        "matched_legitimate_domain": matched_legitimate_domain,
        "domain_brand_consistent": domain_brand_consistent,
        "phishpedia_confidence": phishpedia_confidence,
        "visual_verdict_available": visual_verdict_available,
    }
    reasons: list[str] = []
    p = url_probability if url_probability is not None else 0.0
    heuristic = url_heuristic_score if url_heuristic_score is not None else 0

    # --- Stage 1 alone decides the floor ---------------------------------
    if p < STAGE1_SAFE_MAX and heuristic <= 20:
        reasons.append(f"Stage-1 URL model probability {p:.2f} below safe threshold "
                       f"{STAGE1_SAFE_MAX:.2f}; visual verification not triggered")
        return {"decision": DECISION_SAFE, "risk_score": max(0, min(100, round(p * 50))),
                "reasons": reasons, "evidence": evidence}

    # --- Stage 2 ran (or was requested) -----------------------------------
    brand_consistent = domain_brand_consistent is True
    brand_mismatch = domain_brand_consistent is False
    strong_brand = (
        visual_verdict_available
        and brand_detected is not None
        and brand_similarity is not None
        and brand_similarity >= VISUAL_IMPERSONATION_MIN
    )

    if strong_brand and brand_mismatch and p >= STAGE1_HIGH_MIN:
        reasons.append(
            f"Stage-1 model high-confidence phishing (p={p:.2f})")
        reasons.append(
            f"Visual impersonation: '{brand_detected}' brand detected "
            f"(similarity {brand_similarity:.2f}) but page domain does not "
            f"belong to {matched_legitimate_domain or 'the brand'}")
        return {"decision": DECISION_BLOCK, "risk_score": 95, "reasons": reasons,
                "evidence": evidence}

    if strong_brand and brand_mismatch:
        reasons.append(
            f"Visual impersonation: '{brand_detected}' brand rendered on a "
            f"domain not registered to it (similarity {brand_similarity:.2f}); "
            f"Stage-1 probability {p:.2f}")
        return {"decision": DECISION_BLOCK, "risk_score": max(85, round(max(p, brand_similarity) * 100) - 5),
                "reasons": reasons, "evidence": evidence}

    if strong_brand and brand_consistent:
        reasons.append(
            f"Page IS the real '{brand_detected}' site (brand matches its "
            f"registered domain) — Stage-1 suspicion {p:.2f} likely a false alarm")
        return {"decision": DECISION_WARN, "risk_score": max(0, min(60, round(p * 60))),
                "reasons": reasons, "evidence": evidence}

    if visual_verdict_available:
        if brand_detected is None:
            reasons.append(
                f"No known brand in the screenshot; Stage-1 probability {p:.2f} "
                f"stands on lexical evidence alone")
        else:
            reasons.append(
                f"Weak brand match ('{brand_detected}' @ {brand_similarity}) — "
                f"not conclusive; Stage-1 probability {p:.2f}")
        # REVIEW band: suspicious lexical, inconclusive visual.
        decision = DECISION_BLOCK if p >= STAGE1_HIGH_MIN and heuristic >= 40 else DECISION_REVIEW
        score = max(60, min(90, round(p * 100) - (0 if decision == DECISION_REVIEW else 0)))
        return {"decision": decision, "risk_score": score, "reasons": reasons,
                "evidence": evidence}

    # Stage 2 requested but no visual verdict available (engine missing,
    # screenshot failed, job pending) — Stage-1 evidence only.
    if p >= STAGE1_HIGH_MIN:
        reasons.append(f"Stage-1 high-confidence phishing (p={p:.2f}); "
                       f"visual verification unavailable")
        return {"decision": DECISION_BLOCK, "risk_score": max(85, round(p * 100)),
                "reasons": reasons, "evidence": evidence}
    if p >= STAGE1_SUSPICIOUS_MIN:
        reasons.append(f"Stage-1 suspicious (p={p:.2f}); visual evidence unavailable — "
                       f"manual review recommended")
        return {"decision": DECISION_REVIEW, "risk_score": max(55, round(p * 100) - 10),
                "reasons": reasons, "evidence": evidence}
    reasons.append(f"Stage-1 borderline (p={p:.2f}) with heuristics {heuristic}")
    return {"decision": DECISION_WARN, "risk_score": max(30, round(p * 80)),
            "reasons": reasons, "evidence": evidence}
