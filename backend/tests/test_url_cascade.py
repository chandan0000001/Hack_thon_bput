"""Unit tests for the cascaded URL pipeline P0/P2 fixes.

Covers:
  * URL model registry — schema bound to version (v3/v3.1 = 19 features,
    v4 = 29 features) and artifact resolution
  * blend_scores_url — ML confidence floor (a high model probability can no
    longer be masked by quiet heuristics) while staying monotonic
  * score_with_ml policy dispatch (only policy='url' uses the floor)
  * evidence_fusion — cascade gate, block/review/warn decisions, and the
    no-averaging guarantee (evidence fields are echoed, not blended)
  * phishpedia_engine.logo_matching — cosine match + domain-map loading
"""

import pytest

from app.services.evidence_fusion import (
    DECISION_BLOCK,
    DECISION_REVIEW,
    DECISION_SAFE,
    DECISION_WARN,
    STAGE1_SUSPICIOUS_MIN,
    fuse_url_evidence,
    stage2_required,
)
from app.services.ml_inference import (
    URL_MODEL_REGISTRY,
    _ml_confidence_floor,
    blend_scores,
    blend_scores_url,
    score_with_ml,
    url_feature_schema,
    url_model_version,
)
from app.services.scoring_service import get_severity


# ---------------------------------------------------------------------------
# Registry / schema binding
# ---------------------------------------------------------------------------

def test_registry_binds_schema_per_version():
    assert URL_MODEL_REGISTRY["v3.1"]["schema"] == "v3"
    assert URL_MODEL_REGISTRY["v3.1"]["artifact"] == "url_xgb_v3.1.pkl"
    assert URL_MODEL_REGISTRY["v4"]["schema"] == "v4"
    assert URL_MODEL_REGISTRY["v4"]["artifact"] == "url_xgb_v4.pkl"


def test_url_feature_schema_follows_calibration():
    version = url_model_version()
    expected = URL_MODEL_REGISTRY.get(version, {}).get("schema", "v1")
    assert url_feature_schema() == expected


# ---------------------------------------------------------------------------
# Blend policy
# ---------------------------------------------------------------------------

def test_generic_blend_masks_high_ml_on_clean_url():
    # The documented defect: 0.99 model probability with zero heuristics -> 54.
    assert blend_scores(0, 0.99) == 54


def test_url_floor_prevents_masking():
    assert blend_scores_url(0, 0.99) >= 88
    assert blend_scores_url(0, 0.90) >= 75


def test_url_floor_is_monotone_in_ml():
    prev = -1
    p = 0.0
    while p <= 1.0:
        score = blend_scores_url(5, p)
        assert score >= prev
        prev = score
        p += 0.05


def test_url_floor_never_lowers_heuristic():
    # Heuristic verdict must survive: ML low + heuristics high stays high.
    assert blend_scores_url(80, 0.1) == 80
    # And ML can never pull a strong heuristic verdict down.
    assert blend_scores_url(95, 0.0) == 95


def test_floor_anchors_reach_block_band():
    # 0.97+ model confidence must map into the block tier (>= 85).
    assert _ml_confidence_floor(0.97) >= 85
    assert _ml_confidence_floor(1.0) >= 90
    assert _ml_confidence_floor(0.3) == 0


def test_score_with_ml_policy_dispatch():
    indicators = [{"type": "ml_model", "probability": 0.99, "value": "url_xgb_v3.1.pkl", "severity": "critical"}]
    generic = score_with_ml(indicators)
    url = score_with_ml(indicators, policy="url")
    assert generic[1] == 54
    assert url[1] >= 88


# ---------------------------------------------------------------------------
# Evidence fusion
# ---------------------------------------------------------------------------

def test_cascade_gate_skips_stage2_for_safe_urls():
    assert stage2_required(0.10) is False
    assert stage2_required(None) is False
    assert stage2_required(STAGE1_SUSPICIOUS_MIN) is True


def test_fusion_safe_when_stage1_quiet():
    out = fuse_url_evidence(url_probability=0.05, url_heuristic_score=0)
    assert out["decision"] == DECISION_SAFE


def test_fusion_blocks_on_brand_domain_mismatch():
    out = fuse_url_evidence(
        url_probability=0.92,
        url_heuristic_score=10,
        brand_detected="PayPal",
        brand_similarity=0.93,
        matched_legitimate_domain="paypal.com",
        domain_brand_consistent=False,
        phishpedia_confidence=0.9,
        visual_verdict_available=True,
    )
    assert out["decision"] == DECISION_BLOCK
    # No-averaging guarantee: every evidence field survives untouched.
    assert out["evidence"]["brand_detected"] == "PayPal"
    assert out["evidence"]["url_probability"] == 0.92


def test_fusion_downgrades_when_brand_is_legit():
    # It really is paypal.com — visual evidence says the model misfired.
    out = fuse_url_evidence(
        url_probability=0.93,
        url_heuristic_score=5,
        brand_detected="PayPal",
        brand_similarity=0.95,
        matched_legitimate_domain="paypal.com",
        domain_brand_consistent=True,
        phishpedia_confidence=0.95,
        visual_verdict_available=True,
    )
    assert out["decision"] in (DECISION_WARN, DECISION_REVIEW)
    assert out["decision"] != DECISION_BLOCK


def test_fusion_review_when_visual_unavailable():
    out = fuse_url_evidence(url_probability=0.70, url_heuristic_score=0,
                            visual_verdict_available=False)
    assert out["decision"] == DECISION_REVIEW


def test_fusion_block_without_visual_on_very_high_ml():
    out = fuse_url_evidence(url_probability=0.97, url_heuristic_score=0,
                            visual_verdict_available=False)
    assert out["decision"] == DECISION_BLOCK


def test_fusion_scores_map_to_valid_severity():
    out = fuse_url_evidence(url_probability=0.9, url_heuristic_score=15,
                            brand_detected="Netflix", brand_similarity=0.9,
                            matched_legitimate_domain="netflix.com",
                            domain_brand_consistent=False,
                            phishpedia_confidence=0.8,
                            visual_verdict_available=True)
    assert get_severity(out["risk_score"]) in {"medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Phishpedia matching primitives (no torch required)
# ---------------------------------------------------------------------------

def test_logo_matching_cosine_and_threshold():
    from app.services.phishpedia_engine.logo_matching import match_logo

    domain_map = {
        "PayPal": {"domains": ["paypal.com"], "embedding": [1.0, 0.0, 0.0]},
        "Netflix": {"domains": ["netflix.com"], "embedding": [0.0, 1.0, 0.0]},
    }
    hit = match_logo([0.99, 0.1, 0.0], domain_map, threshold=0.82)
    assert hit is not None
    assert hit["brand"] == "PayPal"
    assert hit["legitimate_domain"] == "paypal.com"
    miss = match_logo([0.0, 0.0, 1.0], domain_map, threshold=0.82)
    assert miss is None


def test_logo_matching_tolerates_missing_embeddings():
    from app.services.phishpedia_engine.logo_matching import match_logo

    domain_map = {"Acme": {"domains": ["acme.com"], "embedding": None}}
    assert match_logo([1.0, 2.0], domain_map) is None
