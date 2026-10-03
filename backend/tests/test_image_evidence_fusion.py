"""Image evidence-fusion + secondary detector tests (fiximage.md §26).

Unit-level suite for the deterministic fusion layer:
  * gate behaviour (should_run_secondary_model)
  * fusion cases (fuse_image_evidence) — agreement, disagreement, fallbacks
  * secondary adapter contract (predict_secondary_image)
  * detector integration (analyze_media image pipeline with patched models)

No torch/timm required: predictors are monkeypatched, the real Model A /
Model B weights are never loaded here.
"""

import pytest

from app.core.config import get_settings
from app.services import deepfake_detector as detector_module
from app.services.image_evidence_fusion import (
    calculate_model_disagreement,
    fuse_image_evidence,
    get_image_detection_confidence,
    should_run_secondary_model,
)
from app.services.secondary_image_detector import (
    convert_sentry_convnext_state_dict,
    predict_secondary_image,
)


@pytest.fixture(autouse=True)
def _reset_settings():
    """Deterministic spec-default thresholds for every test."""
    settings = get_settings()
    monkeypatch_targets = {
        "DEEPFAKE_SECONDARY_ENABLED": True,
        "DEEPFAKE_SECONDARY_LOW_CONFIDENCE": 0.35,
        "DEEPFAKE_SECONDARY_HIGH_CONFIDENCE": 0.65,
        "DEEPFAKE_MODEL_DISAGREEMENT_THRESHOLD": 0.35,
        "DEEPFAKE_SECONDARY_TIMEOUT_SECONDS": 30,
        "ML_ENABLED": True,
    }
    saved = {key: getattr(settings, key) for key in monkeypatch_targets}
    for key, value in monkeypatch_targets.items():
        setattr(settings, key, value)
    yield
    for key, value in saved.items():
        setattr(settings, key, value)


# ---------------------------------------------------------------------------
# Gate: should_run_secondary_model
# ---------------------------------------------------------------------------

def test_gate_skips_when_model_a_confident_fake():
    assert should_run_secondary_model(0.92, forensic_probability=0.10, splice_score=1.0) is False


def test_gate_skips_when_model_a_confident_real_and_forensics_clean():
    assert should_run_secondary_model(0.08, forensic_probability=0.05, splice_score=1.0) is False


def test_gate_runs_when_model_a_uncertain():
    assert should_run_secondary_model(0.51, forensic_probability=0.05, splice_score=1.0) is True


def test_gate_runs_on_forensic_contradiction_of_confident_real():
    # Model A says real, but strong ELA splice evidence disagrees.
    assert should_run_secondary_model(0.08, forensic_probability=0.60, splice_score=1.0) is True
    assert should_run_secondary_model(0.08, forensic_probability=0.05, splice_score=4.5) is True


def test_gate_skips_confident_fake_even_with_clean_forensics():
    # Spec §8: a confident Model A fake verdict (0.92) does NOT require
    # Model B — the second model is verification, not a default second pass.
    assert should_run_secondary_model(0.92, forensic_probability=0.10, splice_score=1.0) is False


def test_gate_runs_when_model_a_unavailable():
    assert should_run_secondary_model(None) is True


def test_gate_disabled_by_configuration():
    settings = get_settings()
    settings.DEEPFAKE_SECONDARY_ENABLED = False
    assert should_run_secondary_model(0.51) is False


def test_gate_disabled_by_ml_toggle():
    settings = get_settings()
    settings.ML_ENABLED = False
    assert should_run_secondary_model(0.51) is False


# ---------------------------------------------------------------------------
# Disagreement + confidence helpers
# ---------------------------------------------------------------------------

def test_calculate_model_disagreement():
    assert calculate_model_disagreement(0.82, 0.21) == pytest.approx(0.61)
    assert calculate_model_disagreement(0.90, 0.88) == pytest.approx(0.02)
    assert calculate_model_disagreement(0.90, None) is None
    assert calculate_model_disagreement(None, 0.10) is None


def test_confidence_higher_for_agreement_than_disagreement():
    high = get_image_detection_confidence(0.90, 0.88, 0.05, 1.0)  # agreed fake, silent forensics
    low = get_image_detection_confidence(0.85, 0.20, 0.05, 1.0)
    assert high > 0.8
    assert low < 0.5


# ---------------------------------------------------------------------------
# Fusion: fuse_image_evidence (spec §10 cases)
# ---------------------------------------------------------------------------

def test_fuse_case1_both_models_agree_fake():
    result = fuse_image_evidence(0.90, 0.88, True, 0.10, primary_blended_probability=0.5, splice_score=1.0)
    assert result["probability"] == pytest.approx(0.90)  # max, NOT the average 0.89
    assert result["agreement"] is True
    assert result["secondary_invoked"] is True
    assert result["fallback"] == "none"


def test_fuse_case2_both_models_agree_real():
    result = fuse_image_evidence(0.10, 0.08, True, 0.05, primary_blended_probability=0.5, splice_score=1.0)
    assert result["probability"] == pytest.approx(0.08)  # min — strongest real vote
    assert result["agreement"] is True


def test_fuse_case3_divergent_magnitude_both_lean_fake():
    # |0.95 - 0.55| = 0.40 > 0.35 threshold: both lean fake, conservative
    # resolution takes the WEAKER fake vote — never the average.
    result = fuse_image_evidence(0.95, 0.55, True, 0.05, primary_blended_probability=0.5, splice_score=1.0)
    assert result["disagreement"] == pytest.approx(0.40)
    assert result["probability"] == pytest.approx(0.55)


def test_fuse_case4_strong_opposed_disagreement_is_uncertain():
    result = fuse_image_evidence(0.85, 0.20, True, 0.05, primary_blended_probability=0.5, splice_score=1.0)
    assert result["probability"] == pytest.approx(0.5)  # no confident fake/real call
    assert result["agreement"] is False
    assert result["confidence"] < 0.5
    assert "disagreement" in result["rationale"].lower()


def test_fuse_case5_model_b_unavailable_preserves_existing_pipeline():
    result = fuse_image_evidence(
        0.80,
        None,
        model_b_available=False,
        forensic_probability=0.30,
        primary_blended_probability=0.4321,
        splice_score=1.0,
    )
    assert result["probability"] == pytest.approx(0.4321)  # identity, no recompute
    assert result["fallback"] == "primary_only"
    assert result["secondary_invoked"] is False


def test_fuse_case6_model_a_unavailable_uses_model_b_plus_forensics():
    result = fuse_image_evidence(
        None, 0.80, True, forensic_probability=0.30, splice_score=1.0,
    )
    assert result["probability"] == pytest.approx(0.80)
    assert result["fallback"] == "secondary_only"
    assert result["secondary_invoked"] is True


def test_fuse_case7_both_models_unavailable_forensics_only():
    result = fuse_image_evidence(
        None, None, False, forensic_probability=0.42,
        primary_blended_probability=0.42, splice_score=1.0,
    )
    assert result["probability"] == pytest.approx(0.42)
    assert result["fallback"] == "forensics_only"


def test_fuse_strong_forensic_splice_raises_never_lowers():
    # Priority A: strong splice evidence lifts the fused fake probability.
    result = fuse_image_evidence(0.60, 0.62, True, 0.75, splice_score=4.5, strong_splice_threshold=4.0)
    assert result["probability"] >= 0.75


def test_fuse_weak_splice_with_real_models_stays_low():
    result = fuse_image_evidence(0.05, 0.04, True, 0.05, splice_score=1.2, strong_splice_threshold=4.0)
    assert result["probability"] <= 0.05


def test_fuse_container_mismatch_counts_as_strong_forensics():
    indicators = [{"type": "container_mismatch", "severity": "high"}]
    result = fuse_image_evidence(
        0.30, 0.32, True, 0.55, splice_score=1.0,
        metadata_indicators=indicators, strong_splice_threshold=4.0,
    )
    assert result["probability"] == pytest.approx(0.55)  # raised to forensic probability


def test_fuse_never_averages():
    # (0.90 + 0.10) / 2 = 0.50 must never appear as a silent average.
    result = fuse_image_evidence(0.90, 0.10, True, 0.02, splice_score=0.5)
    assert result["probability"] == pytest.approx(0.5)  # deadlock -> explicit 0.5, flagged
    assert result["agreement"] is False
    assert result["method"] == "calibrated_evidence_fusion"


# ---------------------------------------------------------------------------
# Secondary adapter contract
# ---------------------------------------------------------------------------

def test_adapter_disabled_returns_unavailable():
    get_settings().DEEPFAKE_SECONDARY_ENABLED = False
    result = predict_secondary_image(b"not-a-real-image")
    assert result["available"] is False
    assert "disabled" in result["error"]
    assert result["model"] == "Sentry ConvNeXt Small"


def test_adapter_returns_unavailable_without_torch_backend():
    # In a dependency-free environment the load fails and degrades gracefully.
    result = predict_secondary_image(b"\x89PNG\r\n\x1a\nnot-really")
    # Either loads (has deps) or degrades — but never raises and never 500s.
    assert result["available"] in (True, False)
    if not result["available"]:
        assert result["error"]


def test_sentry_state_dict_conversion():
    # Key shapes follow Lynote's own conversion test (tests/test_model_utils.py).
    raw = {
        "backbone.downsample_layers.0.0.weight": "a",
        "backbone.downsample_layers.0.1.weight": "b",
        "backbone.downsample_layers.1.0.weight": "c",
        "backbone.downsample_layers.1.1.weight": "d",
        "backbone.stages.0.0.depthwise_conv.weight": "e",
        "backbone.stages.0.0.pointwise_conv1.weight": "f",
        "backbone.stages.0.0.pointwise_conv2.weight": "g",
        "backbone.norm3.weight": "h",
        "head.fc.weight": "i",
    }
    converted = convert_sentry_convnext_state_dict(raw)
    assert converted["stem.0.weight"] == "a"
    assert converted["stem.1.weight"] == "b"
    assert converted["stages.1.downsample.0.weight"] == "c"
    assert converted["stages.1.downsample.1.weight"] == "d"
    assert converted["stages.0.blocks.0.conv_dw.weight"] == "e"
    assert converted["stages.0.blocks.0.mlp.fc1.weight"] == "f"
    assert converted["stages.0.blocks.0.mlp.fc2.weight"] == "g"
    assert converted["head.norm.weight"] == "h"
    assert converted["head.fc.weight"] == "i"


# ---------------------------------------------------------------------------
# Detector integration: analyze_media image pipeline
# ---------------------------------------------------------------------------

def _tiny_png() -> bytes:
    """Valid minimal PNG generated with Pillow (decodable, no EXIF)."""
    import io

    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (64, 64), color=(120, 120, 200)).save(buffer, "PNG")
    return buffer.getvalue()


PNG_1PX = _tiny_png()


def _image_result(file_bytes=PNG_1PX, monkeypatch=None, model_a=None, model_b=None, model_b_available=True):
    def fake_predict_a(_bytes):
        return model_a

    def fake_predict_b(_bytes):
        return {
            "probability_ai": model_b if model_b is not None else 0.0,
            "label": "ai" if (model_b or 0) >= 0.5 else "real",
            "model": "Sentry ConvNeXt Small",
            "backend": "sentry-convnext-small",
            "available": model_b_available and model_b is not None,
            **({} if (model_b_available and model_b is not None) else {"error": "simulated runtime failure"}),
        }

    monkeypatch.setattr(detector_module, "predict_image", fake_predict_a)
    monkeypatch.setattr(detector_module, "predict_secondary_image", fake_predict_b)
    return detector_module.analyze_media(file_bytes, "upload.png", "image/png")


def test_analyze_media_model_a_confident_skips_model_b(monkeypatch):
    result = _image_result(monkeypatch=monkeypatch, model_a=0.02)
    assert result["fusion"]["secondary_invoked"] is False
    assert result["fusion"]["fallback"] == "primary_only"
    assert result["model_evidence"]["primary"]["probability"] == pytest.approx(0.02)
    assert result["model_evidence"]["secondary"]["available"] is False
    assert "model_evidence" in result and "fusion" in result and "forensics" in result


def test_analyze_media_uncertain_invokes_model_b_agreement(monkeypatch):
    result = _image_result(monkeypatch=monkeypatch, model_a=0.52, model_b=0.55)
    assert result["fusion"]["secondary_invoked"] is True
    assert result["fusion"]["agreement"] is True
    assert result["manipulation_probability"] == pytest.approx(0.55)
    assert result["model_evidence"]["agreement"] is True
    assert "disagreement" not in result  # within threshold — not flagged


def test_analyze_media_strong_disagreement_flagged(monkeypatch):
    # Model A in the uncertain band (gate opens) with an opposed Model B
    # verdict -> deadlock 0.5 + explicit model_disagreement evidence.
    result = _image_result(monkeypatch=monkeypatch, model_a=0.55, model_b=0.05)
    assert result["fusion"]["agreement"] is False
    assert result["fusion"]["probability"] == pytest.approx(0.5)
    disagreement_types = [i["type"] for i in result["indicators"]]
    assert "model_disagreement" in disagreement_types
    assert result["disagreement"]["flagged"] is True
    flag = next(i for i in result["indicators"] if i["type"] == "model_disagreement")
    assert flag["value"] == "model_a=0.55, model_b=0.05"


def test_analyze_media_model_a_unavailable_uses_model_b(monkeypatch):
    result = _image_result(monkeypatch=monkeypatch, model_a=None, model_b=0.80)
    assert result["fusion"]["fallback"] == "secondary_only"
    assert result["model_evidence"]["primary"]["available"] is False
    assert result["model_evidence"]["secondary"]["probability"] == pytest.approx(0.80)


def test_analyze_media_both_models_unavailable_forensics_only(monkeypatch):
    result = _image_result(monkeypatch=monkeypatch, model_a=None, model_b=None, model_b_available=False)
    assert result["fusion"]["fallback"] == "forensics_only"
    heuristics_only = [i for i in result["indicators"] if i.get("value") == "heuristics-only-fallback"]
    assert heuristics_only


def test_analyze_media_secondary_disabled_keeps_existing_pipeline(monkeypatch):
    get_settings().DEEPFAKE_SECONDARY_ENABLED = False
    result = _image_result(monkeypatch=monkeypatch, model_a=0.51)
    assert result["fusion"]["secondary_invoked"] is False
    assert result["model_evidence"]["secondary"]["available"] is False
    assert "disabled" in result["model_evidence"]["secondary"]["error"]


def test_analyze_media_model_b_runtime_failure_degrades(monkeypatch):
    result = _image_result(
        monkeypatch=monkeypatch, model_a=0.51, model_b=None, model_b_available=False
    )
    # Gate opened, predictor failed -> fusion continues on Model A + forensics.
    assert result["fusion"]["secondary_invoked"] is False
    assert result["fusion"]["fallback"] == "primary_only"
    assert result["model_evidence"]["secondary"]["available"] is False
    assert result["model_evidence"]["secondary"].get("error")


def test_analyze_media_forensics_block_present(monkeypatch):
    result = _image_result(monkeypatch=monkeypatch, model_a=0.02)
    assert result["forensics"]["ela"] is True
    assert isinstance(result["forensics"]["splice_score"], float)
    assert result["forensics"]["metadata"] is True  # synthetic PNG has no EXIF


def test_analyze_media_missing_exif_indicator(monkeypatch):
    result = _image_result(monkeypatch=monkeypatch, model_a=0.02)
    assert any(i["type"] == "missing_exif" for i in result["indicators"])


def test_analyze_media_corrupted_image_raises(monkeypatch):
    with pytest.raises(ValueError):
        detector_module.analyze_media(b"corrupted-not-an-image", "upload.png", "image/png")


def test_analyze_media_unsupported_media_type_raises():
    with pytest.raises(ValueError):
        detector_module.analyze_media(PNG_1PX, "upload.txt", "text/plain")


def test_analyze_media_container_mismatch_indicator(monkeypatch):
    # PNG bytes named .jpg -> container_mismatch is strong forensic evidence;
    # the gate opens (confident real contradicted by forensics) and Model B
    # failing leaves the existing capped pipeline verdict in place.
    monkeypatch.setattr(detector_module, "predict_image", lambda _b: 0.02)
    monkeypatch.setattr(
        detector_module,
        "predict_secondary_image",
        lambda _b: {"available": False, "error": "off"},
    )
    mismatched = detector_module.analyze_media(PNG_1PX, "upload.jpg", "image/jpeg")
    assert any(i["type"] == "container_mismatch" for i in mismatched["indicators"])
    assert mismatched["fusion"]["fallback"] in ("primary_only", "none")


def test_prompt_includes_deterministic_evidence():
    from app.ai.prompt_templates import format_deepfake_user_prompt

    result = {
        "method": "x", "simulated": False, "media_type": "image",
        "authenticity_score": 0.45, "manipulation_probability": 0.55,
        "indicators": [], "risk_score": 55, "severity": "medium",
        "model_evidence": {"primary": {"model": "MobileNetV3-Small", "probability": 0.52},
                           "secondary": {"model": "Sentry ConvNeXt Small", "probability": 0.55},
                           "agreement": True, "disagreement": 0.03},
        "forensics": {"ela": True, "splice_score": 1.5, "metadata": True},
        "fusion": {"method": "calibrated_evidence_fusion", "secondary_invoked": True,
                   "confidence": 0.9, "fallback": "none"},
    }
    prompt = format_deepfake_user_prompt(result, risk_score=55, severity="medium")
    assert "model_evidence" in prompt
    assert "calibrated_evidence_fusion" in prompt
    assert "MobileNetV3-Small" in prompt
    assert "never a new one" in prompt


def test_llm_cannot_override_verdict_system_prompt():
    from app.ai.prompt_templates import DEEPFAKE_SYSTEM_PROMPT

    assert "must NOT re-classify" in DEEPFAKE_SYSTEM_PROMPT
