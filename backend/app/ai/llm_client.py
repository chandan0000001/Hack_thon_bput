"""Multi-Provider Distributed LLM Orchestration Engine.

Supported Providers:
- Groq (Ultra-fast inference: Llama 3.3 70B, Llama 3.1 8B, Mixtral)
- Gemini (Google GenAI: Gemini 2.0 Flash, Gemini 1.5 Flash)
- OpenRouter (Multi-model gateway)

Features:
- Distributed round-robin load distribution across providers.
- Key rotation and circuit breaking within each provider pool.
- Automatic failover: if one provider or key goes down, requests jump to the next without failing.
- Resilient startup: never fails if keys are missing.
- Deterministic heuristic fallback when no keys are configured or all models are exhausted.
"""

import json
import logging
import re
import time
from typing import Any, Optional

import httpx

from app.ai.key_rotator import get_key_rotator
from app.core.config import get_settings

logger = logging.getLogger("cyberguard.llm_engine")

OPENROUTER_CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

REQUEST_TIMEOUT_SECONDS = 4.0
HTTP_REFERER = "https://cyberguard.local"
APP_TITLE = "CYBERGUARD"


def _normalize_severity(score: int) -> str:
    if score <= 20:
        return "safe"
    if score <= 40:
        return "low"
    if score <= 60:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


def _parse_llm_content(content: str) -> Optional[dict[str, Any]]:
    """Parse JSON defensively from LLM output by extracting outermost braces or code fences."""
    if not content:
        return None

    content = content.strip()

    # Strip thinking blocks if present (e.g. <think>...</think>)
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", content, flags=re.IGNORECASE).strip()
    if not cleaned:
        cleaned = content

    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Check for markdown code fences (```json ... ``` or ``` ...)
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, flags=re.IGNORECASE)
    if fence_match:
        try:
            parsed = json.loads(fence_match.group(1).strip())
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    # Find outermost braces
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = cleaned[start : end + 1]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    # Fallback: if model provided non-JSON plaintext explanation describing threat/benign status
    if len(cleaned) > 20 and not cleaned.startswith("{"):
        lowered = cleaned.lower()
        if "risk" in lowered or "safe" in lowered or "threat" in lowered or "phishing" in lowered or "benign" in lowered:
            return {"explanation": cleaned}

    return None


def generate_heuristic_explanation(
    module: str,
    indicators: list[dict[str, Any]],
    raw_data: Optional[dict[str, Any]] = None,
    risk_score: int = 0,
) -> dict[str, Any]:
    """Generate high-quality heuristic explanation and MITRE mappings aligned with severity."""
    raw_data = raw_data or {}
    severity = _normalize_severity(risk_score)

    if severity == "safe":
        return {
            "explanation": (
                f"Safe (Risk Score {risk_score}/100): Heuristic analysis and trained models evaluated "
                "this artifact as benign. No malicious links, credential harvesting attempts, "
                "or deceptive anomalies were identified."
            ),
            "mitre_techniques": [],
            "recommended_actions": ["No action required", "Permit standard handling"],
        }

    descriptions = [ind.get("description") for ind in indicators if isinstance(ind, dict) and ind.get("description")]
    summary_reasons = "; ".join(descriptions[:3]) if descriptions else "Multiple forensic indicators matched."

    # Module-specific defaults
    if module == "phishing":
        mitre = [
            {"id": "T1566.001", "name": "Spearphishing Attachment/Link"},
            {"id": "T1566.002", "name": "Spearphishing Link"},
        ]
        actions = ["Quarantine email", "Warn the user", "Block suspicious URL"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Phishing indicators detected: {summary_reasons}. "
            "The message attempts to deceive the recipient into interacting with malicious links or disclosing credentials."
        )

    elif module == "url":
        mitre = [
            {"id": "T1566.002", "name": "Spearphishing Link"},
            {"id": "T1204.001", "name": "Malicious Link"},
        ]
        actions = ["Block suspicious URL", "Warn the user"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Suspicious URL characteristics identified: {summary_reasons}. "
            "The URL displays markers common in malware delivery, credential harvesting, or deceptive redirects."
        )

    elif module == "impersonation":
        mitre = [
            {"id": "T1656", "name": "Impersonation"},
            {"id": "T1566", "name": "Phishing"},
        ]
        actions = ["Report impersonation", "Warn the user", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Digital impersonation pattern detected: {summary_reasons}. "
            "The communication mimics authority figures with urgency, unusual financial requests, or secrecy demands."
        )

    elif module == "account_takeover":
        mitre = [
            {"id": "T1110.003", "name": "Password Spraying"},
            {"id": "T1078", "name": "Valid Accounts"},
        ]
        actions = ["Revoke active session", "Require additional authentication", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Account takeover anomaly detected: {summary_reasons}. "
            "Anomalous authentication behavior indicates potential credential stuffing, brute-forcing, or impossible travel."
        )

    elif module in ("network", "api_abuse"):
        mitre = [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1499", "name": "Endpoint Denial of Service"},
        ]
        actions = ["Block suspicious IP/device", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Network/API threat pattern detected: {summary_reasons}. "
            "Traffic exhibits characteristics of abnormal data exfiltration, command-and-control ports, or rate abuse."
        )

    elif module == "deepfake":
        mitre = [
            {"id": "T1656", "name": "Impersonation via Synthetic Media"},
        ]
        actions = ["Flag multimedia for manual verification", "Notify administrator/SOC"]
        explanation = (
            f"{severity.capitalize()} Risk (Score {risk_score}/100): Media manipulation / synthetic artifact detected: {summary_reasons}. "
            "Forensics analysis indicates anomalous error-level variance, spectral distortion, or AI synthesis signatures."
        )

    elif module == "assistant":
        mitre = []
        actions = ["Review active alerts", "Verify endpoint status"]
        explanation = (
            "SOC Assistant Telemetry Summary: Active security posture is monitored. "
            "Telemetry indicators and past alerts are indexed for investigation. "
            "Please refer to the Alerts table for granular threat data."
        )

    else:
        mitre = [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
        actions = ["Notify administrator/SOC", "Escalate the incident for investigation"]
        explanation = f"{severity.capitalize()} Risk (Score {risk_score}/100): Threat activity detected: {summary_reasons}."

    return {
        "explanation": explanation,
        "mitre_techniques": mitre,
        "recommended_actions": actions,
    }


def generate_heuristic_fallback_explanation(
    score: int,
    indicators: Optional[list[Any]] = None,
    mitre_tags: Optional[list[Any]] = None,
    recommended_actions: Optional[list[Any]] = None,
    module: Optional[str] = None,
) -> str:
    """Construct a concise, factual paragraph based purely on heuristic data when LLM times out."""
    safe_indicators = indicators if isinstance(indicators, (list, tuple)) else []
    safe_mitre_tags = mitre_tags if isinstance(mitre_tags, (list, tuple)) else []
    safe_recommended_actions = recommended_actions if isinstance(recommended_actions, (list, tuple)) else []

    ind_labels: list[str] = []
    for ind in safe_indicators:
        if not ind:
            continue
        if isinstance(ind, dict):
            label = ind.get("description") or ind.get("value") or ind.get("type")
            if label:
                ind_labels.append(str(label))
        elif isinstance(ind, str):
            ind_labels.append(ind)
        elif hasattr(ind, "description") and ind.description:
            ind_labels.append(str(ind.description))
        elif hasattr(ind, "type") and ind.type:
            ind_labels.append(str(ind.type))

    indicators_str = "; ".join(ind_labels[:3]) if ind_labels else "system behavioral heuristics"

    tag_labels: list[str] = []
    for tag in safe_mitre_tags:
        if not tag:
            continue
        if isinstance(tag, dict):
            tag_id = tag.get("id") or ""
            tag_name = tag.get("name") or ""
            if tag_id and tag_name:
                tag_labels.append(f"{tag_id} ({tag_name})")
            elif tag_id:
                tag_labels.append(str(tag_id))
            elif tag_name:
                tag_labels.append(str(tag_name))
        elif isinstance(tag, str):
            tag_labels.append(tag)
        elif hasattr(tag, "id"):
            tag_labels.append(f"{getattr(tag, 'id', '')} {getattr(tag, 'name', '')}".strip())
    tags_str = ", ".join(tag_labels) if tag_labels else "None"

    if not safe_recommended_actions and module:
        try:
            fast_meta = generate_heuristic_explanation(module=module, indicators=safe_indicators, risk_score=score)
            safe_recommended_actions = fast_meta.get("recommended_actions", [])
        except Exception:
            safe_recommended_actions = []

    act_labels: list[str] = []
    for act in safe_recommended_actions:
        if not act:
            continue
        if isinstance(act, dict):
            act_text = act.get("action") or act.get("description")
            if act_text:
                act_labels.append(str(act_text))
        elif isinstance(act, str):
            act_labels.append(act)
        elif hasattr(act, "action") and getattr(act, "action", None):
            act_labels.append(str(act.action))
    actions_str = ", ".join(act_labels[:3]) if act_labels else "Review security alerts and verify source"

    return (
        f"LLM timed out. Heuristic analysis: Risk score {score} driven by {indicators_str}. "
        f"MITRE tags: {tags_str}. Recommended action: {actions_str}."
    )



def _enforce_severity_consistency(output: dict[str, Any], risk_score: int) -> dict[str, Any]:
    """Ensure LLM generated explanation and MITRE techniques strictly match assessed severity."""
    severity = _normalize_severity(risk_score)
    if severity == "safe":
        output["mitre_techniques"] = []
        raw_exp = str(output.get("explanation", "")).strip()
        lowered = raw_exp.lower()
        contradictory = any(
            phrase in lowered
            for phrase in [
                "high risk",
                "critical risk",
                "medium-high risk",
                "medium risk",
                "fake order notification",
                "exhibits multiple phishing indicators",
                "potential lure for credential harvesting",
            ]
        )
        if contradictory or not lowered.startswith("safe"):
            output["explanation"] = (
                f"Safe (Risk Score {risk_score}/100): Automated heuristics and trained ML models verified "
                "this content as benign with a low risk probability. No deceptive links, credential harvesting, "
                "or social engineering indicators were detected."
            )
        output["recommended_actions"] = ["No action required", "Permit standard handling"]
    return output


async def _call_openrouter_api(
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> tuple[int, Optional[dict[str, Any]]]:
    """Execute chat completion against OpenRouter API."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": HTTP_REFERER,
        "X-Title": APP_TITLE,
    }
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": f"{system_prompt}\nIMPORTANT: You must respond ONLY with a valid JSON object matching the requested schema. Do NOT include markdown code fences or conversational text.",
            },
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
    }
    response = await client.post(OPENROUTER_CHAT_URL, headers=headers, json=payload)
    if response.status_code == 200:
        body = response.json()
        content = body["choices"][0]["message"]["content"]
        return 200, _parse_llm_content(content)
    return response.status_code, None


async def _call_groq_api(
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> tuple[int, Optional[dict[str, Any]]]:
    """Execute chat completion against Groq Cloud API with JSON response format."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": f"{system_prompt}\nIMPORTANT: You must respond ONLY with a valid JSON object matching the requested schema. Do NOT include markdown code fences or conversational text.",
            },
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }
    response = await client.post(GROQ_CHAT_URL, headers=headers, json=payload)
    if response.status_code == 400 and "response_format" in response.text:
        del payload["response_format"]
        response = await client.post(GROQ_CHAT_URL, headers=headers, json=payload)
    if response.status_code == 200:
        body = response.json()
        choices = body.get("choices", [])
        if choices:
            content = choices[0]["message"]["content"]
            return 200, _parse_llm_content(content)
    return response.status_code, None


async def _call_gemini_api(
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> tuple[int, Optional[dict[str, Any]]]:
    """Execute generateContent against Google Gemini API with JSON response mime type."""
    url = f"{GEMINI_BASE_URL}/{model}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    combined_prompt = (
        f"System Instructions:\n{system_prompt}\n\n"
        "IMPORTANT: You must respond ONLY with a valid JSON object matching the requested schema. "
        "Do NOT include markdown code fences or conversational text.\n\n"
        f"User Request:\n{user_prompt}"
    )
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": combined_prompt}],
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
        },
    }
    response = await client.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        body = response.json()
        candidates = body.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts:
                content = parts[0].get("text", "")
                return 200, _parse_llm_content(content)
    return response.status_code, None


async def call_llm(
    system_prompt: str,
    user_prompt: str,
    module: str = "general",
    indicators: Optional[list[dict[str, Any]]] = None,
    raw_data: Optional[dict[str, Any]] = None,
    risk_score: int = 0,
) -> dict[str, Any]:
    """Multi-provider distributed LLM caller with round-robin load distribution, key rotation, and failover."""
    settings = get_settings()
    indicators = indicators or []
    rotator = get_key_rotator()
    start_time = time.time()
    max_total_budget = getattr(settings, "LLM_TIMEOUT_SECONDS", 6.0)
    per_request_timeout = getattr(settings, "LLM_REQUEST_TIMEOUT_SECONDS", REQUEST_TIMEOUT_SECONDS)

    # Pre-compute heuristic fallback
    heuristic_fallback = generate_heuristic_explanation(
        module=module,
        indicators=indicators,
        raw_data=raw_data,
        risk_score=risk_score,
    )

    configured_providers = rotator.get_configured_providers()
    if not configured_providers:
        logger.info(
            "No LLM provider keys configured across any provider (Groq, Gemini, OpenRouter). "
            "Using synthesized heuristic explanation for %s alert.",
            module,
        )
        return _enforce_severity_consistency(heuristic_fallback, risk_score)

    # Distributed provider ordering: prioritize primary configured provider with healthy keys
    start_provider = await rotator.get_next_provider(configured_providers)
    if start_provider and start_provider in configured_providers:
        start_idx = configured_providers.index(start_provider)
        providers_to_try = configured_providers[start_idx:] + configured_providers[:start_idx]
    else:
        providers_to_try = list(configured_providers)

    async with httpx.AsyncClient(timeout=httpx.Timeout(per_request_timeout)) as client:
        for provider in providers_to_try:
            if time.time() - start_time >= max_total_budget:
                logger.warning("Overall LLM time budget (%.1fs) reached; immediately using heuristic fallback", max_total_budget)
                return _enforce_severity_consistency(heuristic_fallback, risk_score)

            pool = rotator._pools.get(provider)
            if pool and pool.key_count > 0 and pool.healthy_count == 0:
                logger.info("[%s] All keys in pool are down; jumping to next provider", provider)
                continue

            # Determine models for this provider
            if provider == "groq":
                models = [settings.GROQ_MODEL] + [m for m in settings.groq_fallback_models_list if m != settings.GROQ_MODEL]
            elif provider == "gemini":
                models = [settings.GEMINI_MODEL] + [m for m in settings.gemini_fallback_models_list if m != settings.GEMINI_MODEL]
            else:
                models = [settings.OPENROUTER_MODEL] + [m for m in settings.fallback_models_list if m != settings.OPENROUTER_MODEL]

            key_count = pool.key_count if pool else 1
            max_key_attempts = max(1, key_count)

            provider_succeeded = False
            for model in models:
                if provider_succeeded or (time.time() - start_time >= max_total_budget):
                    break

                for _ in range(max_key_attempts):
                    if time.time() - start_time >= max_total_budget:
                        break

                    api_key, masked_key = await rotator.get_next_key(provider=provider, allow_downed=False)
                    if not api_key:
                        break

                    try:
                        if provider == "groq":
                            status_code, parsed = await _call_groq_api(client, api_key, model, system_prompt, user_prompt)
                        elif provider == "gemini":
                            status_code, parsed = await _call_gemini_api(client, api_key, model, system_prompt, user_prompt)
                        else:
                            status_code, parsed = await _call_openrouter_api(client, api_key, model, system_prompt, user_prompt)

                        if status_code == 200 and parsed and ("explanation" in parsed or "reply" in parsed):
                            rotator.mark_key_success(api_key, provider=provider)
                            parsed.setdefault("mitre_techniques", heuristic_fallback["mitre_techniques"])
                            parsed.setdefault("recommended_actions", heuristic_fallback["recommended_actions"])
                            return _enforce_severity_consistency(parsed, risk_score)

                        if status_code == 429:
                            rotator.mark_key_down(api_key, reason="Rate limited (429)", status_code=429, provider=provider)
                            logger.warning("[%s] Key %s rate limited on model %s, rotating key...", provider, masked_key, model)
                            continue

                        if status_code in (401, 402, 403):
                            rotator.mark_key_down(api_key, reason=f"Auth/Quota error ({status_code})", status_code=status_code, provider=provider)
                            logger.warning("[%s] Key %s returned HTTP %s on model %s, rotating key...", provider, masked_key, status_code, model)
                            continue

                        if status_code in (404, 503):
                            logger.warning("[%s] Model %s returned HTTP %s, trying next candidate model...", provider, model, status_code)
                            break  # Try next model

                        logger.warning("[%s] Error on model %s with key %s: HTTP %s", provider, model, masked_key, status_code)
                        break

                    except Exception as exc:
                        rotator.mark_key_down(api_key, reason=f"Network error: {exc}", provider=provider)
                        logger.warning("[%s] Request failed for model %s with key %s: %s", provider, model, masked_key, exc)
                        continue

            logger.warning("Provider '%s' exhausted or unavailable. Jumping to next provider in failover pool...", provider)

    # All providers exhausted or budget exceeded: return deterministic heuristic explanation
    logger.info("All LLM providers exhausted; using synthesized heuristic explanation for %s alert", module)
    return _enforce_severity_consistency(heuristic_fallback, risk_score)


# Backward-compatibility alias
call_openrouter = call_llm
