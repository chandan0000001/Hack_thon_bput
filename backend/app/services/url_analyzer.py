"""Contextual URL analyzer with format-based token scoring adjustments (URL-FP-FIX-V2).

Down-weights query entropy and path length for legitimate cryptographic tokens
(JWT, UUID, Base64, Hex) on clean domains, while maintaining 100% weight for
domain-level threat indicators (typosquatting, suspicious TLD, IP host, subdomain spoofing).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.services.domain_intelligence import lookalike_candidate
from app.services.ml_inference import score_with_ml, url_model_artifact
from app.services.scoring_service import (
    STRONG_MALICIOUS_INDICATOR_TYPES,
    calculate_score,
    get_severity,
    get_url_decision,
)
from app.services.url_detector import analyze_url_heuristics
from app.services.url_token_classifier import COMMON_TLDS, analyze_url_structure


def check_domain_threats(url: str) -> list[dict[str, Any]]:
    """Detect domain-level threats (subdomain spoofing, brand lookalikes) that must

    always maintain 100% weight regardless of tokens.
    """
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except ValueError:
        return []

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return []

    threats: list[dict[str, Any]] = []

    # 1. Subdomain spoofing: deceptive subdomain resembling a registered domain (e.g. clean-domain.com.evil.net)
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 3:
        subdomain_labels = labels[:-2]
        if any(label in COMMON_TLDS for label in subdomain_labels):
            threats.append(
                {
                    "type": "subdomain_spoofing",
                    "value": host,
                    "severity": "high",
                    "description": (
                        "The URL uses a deceptive subdomain structure resembling a registered domain name (subdomain spoofing)."
                    ),
                }
            )

    # 2. Brand typosquatting / lookalike candidate
    brand, reason = lookalike_candidate(host)
    if brand is not None:
        threats.append(
            {
                "type": "brand_typosquatting",
                "value": host,
                "severity": "critical",
                "description": (
                    f"Domain '{host}' is a lookalike / typosquatting candidate for brand '{brand}' ({reason})."
                ),
            }
        )

    return threats


def adjust_indicators_for_tokens(
    indicators: list[dict[str, Any]],
    structure: dict[str, Any],
) -> list[dict[str, Any]]:
    """Heavily down-weight or suppress query/path entropy and length indicators

    when a structured token is detected on a clean domain.
    Domain-level indicators remain untouched at 100% weight.
    """
    if not (structure.get("has_structured_token") and structure.get("domain_is_clean")):
        return indicators

    adjusted: list[dict[str, Any]] = []
    # Token-induced metric indicators to suppress or down-weight on clean domains
    token_induced_types = {
        "url_length",
        "path_length",
        "url_entropy",
        "query_entropy",
        "random_path_segment",
        "excessive_digits",
    }

    for ind in indicators:
        itype = ind.get("type", "")
        if itype in token_induced_types:
            # Down-weighted: suppressed from threat scoring on clean domain
            continue
        adjusted.append(ind)

    # Document token detection as an informational, safe indicator
    adjusted.append(
        {
            "type": "structured_token_clean_domain",
            "value": f"locations={','.join(structure.get('token_locations', []))}",
            "severity": "safe",
            "description": (
                "Mathematical cryptographic/identifier token structure detected on a clean domain. "
                "Query entropy and path length contributions were heavily down-weighted."
            ),
        }
    )
    return adjusted


def analyze_url(url: str) -> dict[str, Any]:
    """Perform full contextual analysis of a single URL."""
    structure = analyze_url_structure(url)
    raw_indicators = analyze_url_heuristics(url)

    # Add domain-level threat indicators if detected and not already present
    domain_threats = check_domain_threats(url)
    existing_types = {i.get("type") for i in raw_indicators}
    for threat in domain_threats:
        if threat["type"] not in existing_types:
            raw_indicators.append(threat)
            existing_types.add(threat["type"])

    # Contextual scoring adjustment
    adjusted_indicators = adjust_indicators_for_tokens(raw_indicators, structure)

    heuristic_score, hybrid_score, ml_probability = score_with_ml(
        adjusted_indicators, policy="url"
    )

    # Guardrail check (URL-FP-FIX-V2 / T4):
    has_token = structure.get("has_structured_token", False)
    has_strong = any(
        i.get("type") in STRONG_MALICIOUS_INDICATOR_TYPES for i in adjusted_indicators
    )

    if has_token and structure.get("domain_is_clean") and not has_strong:
        # Cap severity at medium or low and prevent automatic block
        if hybrid_score > 40:
            hybrid_score = min(hybrid_score, 40)
        severity = get_severity(hybrid_score)
    else:
        severity = get_severity(hybrid_score)

    decision = get_url_decision(
        severity,
        ml_confidence=ml_probability,
        has_structured_token=has_token,
        indicators=adjusted_indicators,
    )

    return {
        "url": url,
        "structure": structure,
        "heuristic_score": heuristic_score,
        "hybrid_score": hybrid_score,
        "ml_probability": ml_probability,
        "severity": severity,
        "decision": decision,
        "indicators": adjusted_indicators,
        "model_version": url_model_artifact(),
    }
