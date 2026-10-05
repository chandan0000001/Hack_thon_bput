"""OpenRouter and Multi-Provider LLM client facade.

Maintains complete backward-compatibility with call_openrouter and exports
enhanced multi-provider orchestration through app.ai.llm_client.
"""

from app.ai.llm_client import (
    APP_TITLE,
    HTTP_REFERER,
    OPENROUTER_CHAT_URL,
    REQUEST_TIMEOUT_SECONDS,
    _enforce_severity_consistency,
    _normalize_severity,
    _parse_llm_content,
    call_llm,
    call_openrouter,
    generate_heuristic_explanation,
    generate_heuristic_fallback_explanation,
)

__all__ = [
    "APP_TITLE",
    "HTTP_REFERER",
    "OPENROUTER_CHAT_URL",
    "REQUEST_TIMEOUT_SECONDS",
    "_enforce_severity_consistency",
    "_normalize_severity",
    "_parse_llm_content",
    "call_llm",
    "call_openrouter",
    "generate_heuristic_explanation",
    "generate_heuristic_fallback_explanation",
]

