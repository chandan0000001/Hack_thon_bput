"""Threat risk scoring engine (Part 3).

Scores are derived purely from heuristic indicator severities; they are
deterministic and never invented by the LLM.
"""

CRITICAL_WEIGHT = 25
HIGH_WEIGHT = 15
MEDIUM_WEIGHT = 5

SEVERITY_WEIGHTS = {
    "critical": CRITICAL_WEIGHT,
    "high": HIGH_WEIGHT,
    "medium": MEDIUM_WEIGHT,
}


def calculate_score(indicators: list[dict]) -> int:
    """Sum severity weights over indicators, capped at 100."""
    total = 0
    for indicator in indicators:
        severity = str(indicator.get("severity", "medium")).lower()
        total += SEVERITY_WEIGHTS.get(severity, 0)
    return min(total, 100)


def get_severity(score: int) -> str:
    """Map a 0-100 score to the severity_level enum values."""
    if score <= 20:
        return "safe"
    if score <= 40:
        return "low"
    if score <= 60:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


# --- EMAIL-ACTION-MATRIX: 4-tier enforcement matrix -------------------------
# The corrected 0.0-1.0 risk score maps deterministically to an enforcement
# tier. These are the canonical machine values surfaced as
# ScanResult.recommended_action; the UI renders them capitalized.
ACTION_PASS = "pass"            # < 0.30  -> deliver, no action
ACTION_NOTIFY = "notify"        # 0.30-0.59 -> deliver + warn the user
ACTION_QUARANTINE = "quarantine"  # 0.60-0.84 -> quarantine, sender untouched
ACTION_BLOCK = "block"          # >= 0.85 -> quarantine + block sender

TIER_PASS_MAX = 0.30
TIER_NOTIFY_MAX = 0.60
TIER_QUARANTINE_MAX = 0.85


def get_recommended_action(score_0_1: float) -> str:
    """Map a 0.0-1.0 risk score to the 4-tier action matrix."""
    if score_0_1 < TIER_PASS_MAX:
        return ACTION_PASS
    if score_0_1 < TIER_NOTIFY_MAX:
        return ACTION_NOTIFY
    if score_0_1 < TIER_QUARANTINE_MAX:
        return ACTION_QUARANTINE
    return ACTION_BLOCK
