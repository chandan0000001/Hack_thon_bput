"""Suite 37 — SE-HARDENING: social-engineering pattern detection for
attachment-lure phishing.

12 checks. Unit checks exercise SEPatternEngine, the monotonic SE blend, and
the confidence assessor directly; HTTP checks run the real manual pipeline
(no raw_headers → auth unavailable must not mask the SE signal).

Check 5 doubles as the D6 eval case: it loads tests/data/synthetic/
se_eval_cases.json (id se_attachment_lure_001) and asserts the registered
expectations (verdict suspicious, risk_min 60, three narrative indicators).
"""

import json
from pathlib import Path

import pytest

from app.services.phishing_detector import analyze_email_heuristics
from app.services.scoring_service import calculate_score
from app.services.se_pattern_engine import (
    ATTACHMENT_REFERENCE_WARNING,
    LOW_CONFIDENCE_NOTE,
    SEPatternEngine,
    assess_confidence,
    blend_se,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "data" / "synthetic" / "se_phishing_attachment_lure.txt"
)
EVAL_CASES_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "data" / "synthetic" / "se_eval_cases.json"
)


def _fixture_parts():
    lines = [l for l in FIXTURE_PATH.read_text().splitlines() if l.strip()]
    subject = lines[1].split("Subject: ", 1)[1]
    body = "\n".join(lines[2:])
    return subject, body


# ---------------------------------------------------------------------------
# Engine units (checks 1-4, 7-8)
# ---------------------------------------------------------------------------

def test_37_01_security_alert_framing():
    out = SEPatternEngine().analyze(
        "We detected a recent sign-in from a new device. Complete security verification now."
    )
    types = [i["type"] for i in out["indicators"]]
    assert "security_alert_framing" in types
    assert out["risk_score"] >= 15


def test_37_02_attachment_lure():
    out = SEPatternEngine().analyze("Please review the attached document right away.")
    types = [i["type"] for i in out["indicators"]]
    assert "attachment_lure" in types
    assert out["risk_score"] >= 15
    assert all(i.get("match_count") for i in out["indicators"])


def test_37_03_bureaucratic_urgency():
    out = SEPatternEngine().analyze("Your access may expire within 24 hours if not confirmed.")
    types = [i["type"] for i in out["indicators"]]
    assert "bureaucratic_urgency" in types
    assert out["risk_score"] >= 10


def test_37_04_combination_rule_adds_45():
    out = SEPatternEngine().analyze(
        "We detected a recent sign-in. Review the attached document to secure your account."
    )
    types = [i["type"] for i in out["indicators"]]
    assert "se_combination_rule" in types
    # framing 15 + lure 15 + combination 45 (single matches)
    assert out["risk_score"] == 75
    combo = next(i for i in out["indicators"] if i["type"] == "se_combination_rule")
    assert combo["severity"] == "high" and combo["weight"] == 45


def test_37_07_authority_impersonation():
    out = SEPatternEngine().analyze("This message was sent by the IT department security team.")
    types = [i["type"] for i in out["indicators"]]
    assert "authority_impersonation" in types
    assert out["risk_score"] >= 10


def test_37_08_vague_threat():
    out = SEPatternEngine().analyze("We noticed suspicious activity and unusual sign-in attempts.")
    types = [i["type"] for i in out["indicators"]]
    assert "vague_threat" in types
    assert out["risk_score"] >= 10


# ---------------------------------------------------------------------------
# Monotonic blend + confidence (checks 9-11)
# ---------------------------------------------------------------------------

def test_37_09_monotonic_strong_heuristic_not_lowered():
    assert blend_se(0.8, 0.3) == 0.8


def test_37_10_monotonic_weak_heuristic_raised_to_blend():
    assert blend_se(0.2, 0.7) == pytest.approx(0.35)


def test_37_11_confidence_low_signals_warning():
    out = assess_confidence(0.4, 0.3, url_indicator_count=0, body="see attached")
    assert out["confidence"] == "low"
    assert LOW_CONFIDENCE_NOTE in out["notes"]
    # Strong ML rescues the label, but weak heuristic + attachment reference
    # still appends the separate-verification note.
    out2 = assess_confidence(0.2, 0.9, url_indicator_count=0, body="see attached")
    assert out2["confidence"] is None
    assert any("attachment-lure pattern detected" in n for n in out2["notes"])


# ---------------------------------------------------------------------------
# Manual pipeline (checks 5-6, 12) — HTTP, no raw_headers
# ---------------------------------------------------------------------------

@pytest.mark.http
async def test_37_05_eval_case_screenshot_email_suspicious(client):
    """D6 eval case se_attachment_lure_001 (registry-driven)."""
    cases = json.loads(EVAL_CASES_PATH.read_text())["cases"]
    case = next(c for c in cases if c["id"] == "se_attachment_lure_001")
    assert case["raw_headers"] is None  # auth must be unavailable, not masking SE

    subject, body = _fixture_parts()
    resp = await client.post(
        "/api/v1/analysis/email",
        json={"sender": case["sender"], "subject": subject, "body": body},
    )
    assert resp.status_code == 200
    data = resp.json()
    types = [i.get("type") for i in data.get("indicators", [])]

    assert data["risk_score"] >= case["risk_min"]
    assert 40 <= data["risk_score"] < 80  # suspicious band
    assert data["severity"] == "high"
    for expected in case["expected_indicators"]:
        assert expected in types


@pytest.mark.http
async def test_37_06_benign_invoice_no_false_positive(client):
    resp = await client.post(
        "/api/v1/analysis/email",
        json={
            "sender": "billing@vendor.example",
            "subject": "September invoice",
            "body": "Hi, please review the attached invoice for the September order. "
                    "Payment is due in 30 days. Thank you.",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] < 40
    assert data["severity"] in ("safe", "low")


@pytest.mark.http
async def test_37_12_warnings_array_both_no_duplicates(client):
    resp = await client.post(
        "/api/v1/analysis/email",
        json={
            "sender": "security-alert@cyberguard.com",
            "subject": "Security verification required",
            "body": "We detected a recent sign-in. Review the attached document "
                    "as soon as possible.",
        },
    )
    assert resp.status_code == 200
    warnings = resp.json().get("warnings") or []
    assert any("no message headers" in w for w in warnings)          # auth warning
    assert ATTACHMENT_REFERENCE_WARNING in warnings                  # attachment warning
    assert len(warnings) == len(set(warnings))                       # no duplicates
