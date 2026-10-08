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


# --- URL-DECISION-POLICY: score -> (verdict, action) for the URL engine ------
# Separates the MODEL SCORE (0-100 + severity) from the SECURITY ACTION taken
# by consumers (dashboard display, browser extension). The policy is explicit
# and monotone; thresholds are configuration, not scattered comparisons.
# Fail-safe note: the browser extension applies this policy but FAILS OPEN on
# backend unavailability (never blocks because CyberGuard is offline) — the
# decision is documented in browser-extension/README.md.
URL_VERDICT_SAFE = "safe"
URL_VERDICT_SUSPICIOUS = "suspicious"
URL_VERDICT_MALICIOUS = "malicious"

URL_ACTION_ALLOW = "allow"
URL_ACTION_WARN = "warn"
URL_ACTION_BLOCK = "block"

# HIGH severity warns by default and blocks only when the model is confident
# (ml probability >= URL_BLOCK_CONFIDENCE) — score alone never blocks, the
# confidence+evidence combination does.
URL_BLOCK_CONFIDENCE = 0.90

STRONG_MALICIOUS_INDICATOR_TYPES = {
    "ip_host",
    "ip_address",
    "brand_in_subdomain",
    "brand_typosquatting",
    "lookalike_domain_confirmed",
    "visual_impersonation",
    "subdomain_spoofing",
    "suspicious_tld",
    "homoglyph_confusable",
    "mixed_script_domain",
    "is_idn",
    "executable_extension",
    "urlhaus_pattern",
    "live_credential_form",
}

_URL_POLICY = {
    "safe": (URL_VERDICT_SAFE, URL_ACTION_ALLOW),
    "low": (URL_VERDICT_SAFE, URL_ACTION_ALLOW),
    "medium": (URL_VERDICT_SUSPICIOUS, URL_ACTION_WARN),
    "high": (URL_VERDICT_SUSPICIOUS, URL_ACTION_WARN),
    "critical": (URL_VERDICT_MALICIOUS, URL_ACTION_BLOCK),
}


def get_url_decision(
    severity: str,
    ml_confidence: float | None = None,
    has_structured_token: bool = False,
    indicators: list[dict] | None = None,
) -> dict:
    """Map URL severity (+ optional ML confidence) to {verdict, action}.

    LOW/MEDIUM follow the blueprint defaults; HIGH escalates to BLOCK only
    with high model confidence; CRITICAL always blocks. Unknown severities
    fail safe to WARN (visible) rather than silently ALLOW.

    GUARDRAIL (URL-FP-FIX-V2 / T4):
    If has_structured_token is True and the only elevated indicators are entropy/length,
    without independent strong malicious evidence, cap maximum severity at MEDIUM (or LOW)
    and prevent an automatic BLOCK. A BLOCK strictly requires independent strong evidence.
    """
    sev = str(severity or "").lower()

    if has_structured_token and indicators is not None:
        has_strong_evidence = any(
            i.get("type") in STRONG_MALICIOUS_INDICATOR_TYPES for i in indicators
        )
        if not has_strong_evidence:
            elevated = [
                i for i in indicators
                if i.get("type") != "ml_model" and i.get("severity") in ("medium", "high", "critical")
            ]
            entropy_length_types = {
                "url_entropy",
                "query_entropy",
                "url_length",
                "path_length",
                "random_path_segment",
                "excessive_digits",
            }
            if all(i.get("type") in entropy_length_types for i in elevated):
                if sev in ("high", "critical"):
                    sev = "medium"

    verdict, action = _URL_POLICY.get(
        sev,
        (URL_VERDICT_SUSPICIOUS, URL_ACTION_WARN),
    )
    if verdict == URL_VERDICT_SUSPICIOUS and sev == "high" \
            and ml_confidence is not None and ml_confidence >= URL_BLOCK_CONFIDENCE:
        if has_structured_token and indicators is not None:
            has_strong_evidence = any(
                i.get("type") in STRONG_MALICIOUS_INDICATOR_TYPES for i in indicators
            )
            if not has_strong_evidence:
                verdict, action = URL_VERDICT_SUSPICIOUS, URL_ACTION_WARN
            else:
                verdict, action = URL_VERDICT_MALICIOUS, URL_ACTION_BLOCK
        else:
            verdict, action = URL_VERDICT_MALICIOUS, URL_ACTION_BLOCK

    # Final blocking safeguard (T4):
    # If structured token is present, a "BLOCK" strictly requires independent strong malicious evidence.
    if action == URL_ACTION_BLOCK and has_structured_token and indicators is not None:
        has_strong = any(
            i.get("type") in STRONG_MALICIOUS_INDICATOR_TYPES for i in indicators
        )
        if not has_strong:
            verdict, action = URL_VERDICT_SUSPICIOUS, URL_ACTION_WARN
            if sev in ("high", "critical"):
                sev = "medium"

    return {"verdict": verdict, "action": action}

