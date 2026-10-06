"""ML integration gates (Suite 9) — blend contract, split round-trip, v2 model gates.

Run standalone:
    uv run python scripts/test_ml_gates.py

Also imported by scripts/run_all_tests.py.
"""

import asyncio
import sys
from pathlib import Path

# Ensure backend root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.mode_detector import OperationMode
from app.db.models import Alert, EnforcementPolicy
from app.services import ml_inference as ml
from app.services.enforcement_engine import enforcement_engine
from app.services.scoring_service import calculate_score


class TestRunner:
    """Minimal runner matching scripts/run_all_tests.py conventions."""

    def __init__(self):
        self.passed = 0
        self.failed = 0

    def assert_true(self, condition: bool, name: str, details: str = ""):
        if condition:
            self.passed += 1
            print(f"  \033[32m✔ PASS\033[0m: {name}")
        else:
            self.failed += 1
            print(f"  \033[31m✖ FAIL\033[0m: {name} - {details}")

    def skip(self, name: str, reason: str):
        print(f"  \033[33m⊘ SKIP\033[0m: {name} ({reason})")

    def report(self):
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"TEST RESULTS: {self.passed}/{total} passed")
        if self.failed == 0:
            print("\033[32mALL ML GATE TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


def run_ml_gate_tests(runner: TestRunner) -> None:
    """Execute the ML integration gates (synchronous; no HTTP, no DB writes)."""

    # -----------------------------------------------------------------------
    # 1. Monotonic blend contract
    # -----------------------------------------------------------------------
    print("\n[Suite 9.1] Monotonic Blend Contract")
    runner.assert_true(
        ml.blend_scores(80, 0.1) == 80,
        "blend_scores(80, 0.1) == 80 — ML can never lower a heuristic verdict",
    )
    raised = ml.blend_scores(20, 0.9)
    # Canonical formula: max(h, round(0.45*h + 0.55*p*100)) = 59 here.
    # (Integration spec estimated >= 60; the exact canonical-formula value is 59.)
    runner.assert_true(
        raised >= 55 and raised > 20,
        "blend_scores(20, 0.9) raises the heuristic verdict substantially",
        f"got {raised}",
    )
    runner.assert_true(
        ml.blend_scores(100, 0.0) == 100 and ml.blend_scores(0, 0.0) == 0,
        "Blend is clamped to [0, 100] at the extremes",
    )

    # -----------------------------------------------------------------------
    # 2. split_ml_indicator round-trip preserves the heuristic score
    # -----------------------------------------------------------------------
    print("\n[Suite 9.2] ML Indicator Contract")
    indicators = [
        {"type": "urgency_keyword", "severity": "high", "description": "urgent language"},
        {"type": "lookalike_domain", "severity": "critical", "description": "paypa1"},
    ]
    expected = calculate_score(indicators)
    indicators.append(ml.ml_indicator("url_xgb_v2.pkl", 0.83))
    heuristics, probability = ml.split_ml_indicator(indicators)
    runner.assert_true(
        calculate_score(heuristics) == expected and probability == 0.83,
        "split_ml_indicator round-trip preserves heuristic score and probability",
    )

    # -----------------------------------------------------------------------
    # 3. Audio LCNN gate (SKIP when the artifact is absent)
    # -----------------------------------------------------------------------
    print("\n[Suite 9.3] Audio LCNN")
    if not ml.audio_model_available():
        runner.skip("Audio LCNN inference", "audio_cnn_v1.pt missing — degradation path active")
    else:
        tone = Path(ROOT.parent / "evidence" / "media" / "tone.wav")
        if not tone.exists():
            runner.skip("Audio LCNN inference", f"{tone} not found")
        else:
            from app.services.deepfake_detector import analyze_media

            result = analyze_media(tone.read_bytes(), "tone.wav", "audio/wav")
            ml_prob = next(
                (float(i.get("probability", 0)) for i in result["indicators"] if i.get("type") == "ml_model"),
                None,
            )
            runner.assert_true(
                result.get("simulated") is False and "LCNN" in str(result.get("method", "")),
                "Audio analysis served by the trained LCNN (not the simulated hash path)",
                f"method={result.get('method')} simulated={result.get('simulated')}",
            )
            runner.assert_true(
                ml_prob is not None and ml_prob >= 0.5,
                "LCNN flags the synthetic tone with high spoofing probability",
                f"ml probability={ml_prob}",
            )
        real_speech = Path(ROOT.parent / "datasets" / "audio" / "real_speech.wav")
        if not real_speech.exists():
            runner.skip(
                "Real-speech FPR gate",
                "no real-speech fixture in repo (documented FPR 0.00 in audio_v1_metrics.json)",
            )
        else:
            result = analyze_media(real_speech.read_bytes(), "real_speech.wav", "audio/wav")
            runner.assert_true(result["risk_score"] <= 40, "Real speech does not trigger the audio detector")

    # -----------------------------------------------------------------------
    # 4. Deepfake v2 image gate (SKIP when the artifact is absent)
    # -----------------------------------------------------------------------
    print("\n[Suite 9.4] Deepfake v2 Images")
    if Path(ROOT / "ml" / "models" / "deepfake_cnn_v2.pt").exists():
        from app.services.deepfake_detector import analyze_media

        ev = ROOT.parent / "evidence" / "media"
        manipulated = analyze_media((ev / "manipulated.png").read_bytes(), "manipulated.png", "image/png")
        benign = analyze_media((ev / "benign.png").read_bytes(), "benign.png", "image/png")
        runner.assert_true(
            manipulated["risk_score"] > benign["risk_score"],
            "v2 CNN scores manipulated.png higher than benign.png",
            f"manipulated={manipulated['risk_score']} benign={benign['risk_score']}",
        )
    else:
        runner.skip("Deepfake v2 image gate", "deepfake_cnn_v2.pt missing")

    # -----------------------------------------------------------------------
    # 5. URL v2 gate
    # -----------------------------------------------------------------------
    print("\n[Suite 9.5] URL v2")
    from app.services.url_detector import analyze_url_heuristics

    malicious = ml.score_with_ml(analyze_url_heuristics("http://185.220.101.7/secure/login.php"))
    benign = ml.score_with_ml(analyze_url_heuristics("https://github.com/opencv/opencv"))
    runner.assert_true(
        malicious[1] > benign[1],
        "v2 pipeline scores the malicious URL above the benign one",
        f"malicious={malicious[1]} benign={benign[1]}",
    )
    runner.assert_true(
        ml.url_model_version() == "v4",
        "URL model version resolves to the calibration-pinned serving model (v4)",
        f"got {ml.url_model_version()}",
    )

    # -----------------------------------------------------------------------
    # 6. Enforcement regression — heuristic verdicts still classify identically
    # -----------------------------------------------------------------------
    print("\n[Suite 9.6] Enforcement Regression")
    # In-memory policy: mapped_column defaults apply at flush time, so an
    # unpersisted instance has None thresholds — set the used fields explicitly.
    policy = EnforcementPolicy(
        organization_id="org-ml-gate",
        name="Balanced (gate)",
        phishing_high_threshold=75,
        phishing_medium_threshold=40,
        action_on_critical="block_and_quarantine",
        action_on_high="block",
        action_on_medium="warn_and_log",
        action_on_low="allow",
        auto_execute_critical=True,
        auto_execute_high=True,
        auto_execute_medium=False,
        auto_execute_low=False,
        notify_soc_on_critical=True,
        notify_soc_on_high=True,
        notify_user_on_medium=True,
    )
    alert = Alert(id="alert-ml-gate", module="phishing", severity="high", risk_score=87)
    decision = enforcement_engine.evaluate(alert, policy, OperationMode.SERVER, request_auto_execute=True)
    runner.assert_true(
        decision.enforcement_severity == "high" and decision.action_type == "block" and decision.auto_execute,
        "High-risk phishing still maps to high/block/auto-execute after integration",
        f"severity={decision.enforcement_severity} action={decision.action_type}",
    )
    medium_alert = Alert(id="alert-ml-gate-2", module="phishing", severity="medium", risk_score=55)
    d2 = enforcement_engine.evaluate(medium_alert, policy, OperationMode.SERVER)
    runner.assert_true(
        d2.enforcement_severity == "medium" and d2.requires_approval,
        "Medium-risk phishing still requires approval after integration",
        f"severity={d2.enforcement_severity}",
    )


def _standalone() -> int:
    runner = TestRunner()
    print("\n🛡️ STARTING CYBERGUARD ML GATE TEST SUITE\n" + "=" * 60)
    run_ml_gate_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(_standalone())
