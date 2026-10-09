"""Distributed Multi-Provider API Key Rotation with Fault-Tolerant Circuit Breaking and Background Re-Release.

Supports:
- Groq (Ultra-low latency inference: Llama 3.3 70B, Llama 3.1 8B, Mixtral)
- Gemini (Google GenAI: Gemini 2.0 Flash, Gemini 1.5 Flash)
- OpenRouter (Multi-model gateway)

Features:
- Distributed round-robin load balancing across keys for each provider.
- Dynamic key pool loading from comma-separated strings or numbered environment variables up to MAX_KEYS (default 10).
- Automatic circuit breaking on HTTP 429 / 401 / 402 / 403 or network exceptions.
- Free-time background probe loop to verify and re-release recovered keys.
- Resilient initialization: missing keys log cleanly and do not interrupt server startup.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.key_rotator")

OPENROUTER_AUTH_URL = "https://openrouter.ai/api/v1/auth/key"
GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models"
GEMINI_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"


def mask_key(key: str) -> str:
    """Mask an API key for safe logging (e.g. gsk_abc...xyz or sk-or...1234)."""
    if not key:
        return "none"
    if len(key) <= 12:
        return f"{key[:3]}...{key[-3:]}"
    return f"{key[:8]}...{key[-4:]}"


@dataclass
class KeyState:
    key: str
    masked: str
    provider: str = "openrouter"
    is_healthy: bool = True
    failure_count: int = 0
    last_failure_time: float = 0.0
    down_reason: str = ""
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    last_probed_time: float = 0.0


class ProviderKeyPool:
    """Manages key rotation, circuit breaking, and health status for a single LLM provider."""

    def __init__(self, provider: str, cooldown_seconds: int = 60, health_check_interval: int = 30) -> None:
        self.provider = provider.lower()
        self._keys: dict[str, KeyState] = {}
        self._key_list: list[str] = []
        self._lock = asyncio.Lock()
        self._rr_index = 0
        self._cooldown_seconds = max(1, cooldown_seconds)
        self._health_check_interval = max(1, health_check_interval)

    def initialize(self, keys: list[str], cooldown_seconds: Optional[int] = None, health_check_interval: Optional[int] = None) -> None:
        if cooldown_seconds is not None:
            self._cooldown_seconds = max(1, cooldown_seconds)
        if health_check_interval is not None:
            self._health_check_interval = max(1, health_check_interval)

        new_dict: dict[str, KeyState] = {}
        new_list: list[str] = []

        for k in keys:
            clean = k.strip()
            if clean and clean not in new_dict:
                existing = self._keys.get(clean)
                if existing:
                    new_dict[clean] = existing
                else:
                    new_dict[clean] = KeyState(key=clean, masked=mask_key(clean), provider=self.provider)
                new_list.append(clean)

        self._keys = new_dict
        self._key_list = new_list

    @property
    def key_count(self) -> int:
        return len(self._key_list)

    @property
    def healthy_count(self) -> int:
        return sum(1 for s in self._keys.values() if s.is_healthy)

    async def get_next_key(self, allow_downed: bool = False) -> tuple[Optional[str], str]:
        """Select next available API key using round-robin across healthy keys."""
        if not self._key_list:
            return None, "none"

        now = time.time()
        async with self._lock:
            # Check cooldown expiration for any downed keys
            for state in self._keys.values():
                if not state.is_healthy and (now - state.last_failure_time >= self._cooldown_seconds):
                    state.is_healthy = True
                    state.down_reason = "cooldown expired"
                    logger.info("[%s] Key %s cooldown expired; re-released to active pool", self.provider, state.masked)

            healthy = [self._keys[k] for k in self._key_list if self._keys[k].is_healthy]

            if healthy:
                selected = healthy[self._rr_index % len(healthy)]
                self._rr_index = (self._rr_index + 1) % len(healthy)
                selected.total_requests += 1
                return selected.key, selected.masked

            if not allow_downed:
                return None, "none"

            # If all keys are down and caller explicitly permits downed keys, fall back to least-recently failed
            logger.warning(
                "[%s] All %d API keys are currently marked down! Selecting oldest key for retry.",
                self.provider,
                len(self._key_list),
            )
            oldest = min(self._keys.values(), key=lambda s: s.last_failure_time)
            oldest.total_requests += 1
            return oldest.key, oldest.masked

    def mark_key_down(self, key: str, reason: str, status_code: Optional[int] = None) -> None:
        state = self._keys.get(key)
        if not state:
            return

        state.is_healthy = False
        state.last_failure_time = time.time()
        state.failure_count += 1
        state.total_failures += 1
        state.down_reason = f"{reason} (HTTP {status_code})" if status_code else reason

        logger.warning(
            "[%s] Marked API key %s DOWN: %s. Active pool: %d/%d healthy",
            self.provider,
            state.masked,
            state.down_reason,
            self.healthy_count,
            len(self._keys),
        )

    def mark_key_success(self, key: str) -> None:
        state = self._keys.get(key)
        if state:
            state.is_healthy = True
            state.total_successes += 1
            state.failure_count = 0
            state.down_reason = ""

    async def probe_key(self, state: KeyState) -> bool:
        """Probe key against provider health check endpoint."""
        state.last_probed_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                if self.provider == "openrouter":
                    res = await client.get(
                        OPENROUTER_AUTH_URL,
                        headers={
                            "Authorization": f"Bearer {state.key}",
                            "HTTP-Referer": "https://cyberguard.local",
                            "X-Title": "CYBERGUARD Health Check",
                        },
                    )
                elif self.provider == "groq":
                    res = await client.get(
                        GROQ_MODELS_URL,
                        headers={"Authorization": f"Bearer {state.key}"},
                    )
                elif self.provider == "gemini":
                    res = await client.get(f"{GEMINI_MODELS_URL}?key={state.key}")
                else:
                    return False

                if res.status_code == 200:
                    state.is_healthy = True
                    state.failure_count = 0
                    state.down_reason = ""
                    logger.info("[%s] Health probe succeeded for key %s. Re-released into pool.", self.provider, state.masked)
                    return True
                if res.status_code in (429, 401, 402, 403):
                    state.last_failure_time = time.time()
                    state.down_reason = f"Probe returned HTTP {res.status_code}"
                    logger.debug("[%s] Health probe for key %s returned HTTP %s (remains down).", self.provider, state.masked, res.status_code)
                    return False
        except Exception as exc:
            state.last_failure_time = time.time()
            logger.debug("[%s] Health probe exception for key %s: %s", self.provider, state.masked, exc)
            return False
        return False

    def get_status(self) -> list[dict[str, Any]]:
        now = time.time()
        result = []
        for state in self._keys.values():
            if not state.is_healthy and (now - state.last_failure_time >= self._cooldown_seconds):
                state.is_healthy = True
                state.down_reason = "cooldown expired"
            cooldown_remaining = max(0, int(self._cooldown_seconds - (now - state.last_failure_time))) if not state.is_healthy else 0
            result.append({
                "masked_key": state.masked,
                "provider": self.provider,
                "is_healthy": state.is_healthy,
                "failure_count": state.failure_count,
                "down_reason": state.down_reason,
                "cooldown_remaining_seconds": cooldown_remaining,
                "total_requests": state.total_requests,
                "total_successes": state.total_successes,
                "total_failures": state.total_failures,
            })
        return result


class ApiKeyRotator:
    """Multi-provider distributed LLM key rotator with circuit breaking, failover, and background health checks."""

    def __init__(self) -> None:
        self._pools: dict[str, ProviderKeyPool] = {
            "openrouter": ProviderKeyPool("openrouter"),
            "groq": ProviderKeyPool("groq"),
            "gemini": ProviderKeyPool("gemini"),
        }
        self._default_provider = "openrouter"
        self._provider_rr_index = 0
        self._provider_lock = asyncio.Lock()
        self._background_task: Optional[asyncio.Task] = None
        self._running = False
        self._initialized = False

    def initialize(
        self,
        keys: list[str],
        cooldown_seconds: int = 60,
        health_check_interval: int = 30,
        provider: str = "openrouter",
    ) -> None:
        """Initialize or reconfigure a specific provider pool (defaults to openrouter for backward compatibility)."""
        prov = provider.lower()
        if prov not in self._pools:
            self._pools[prov] = ProviderKeyPool(prov, cooldown_seconds, health_check_interval)
        self._pools[prov].initialize(keys, cooldown_seconds, health_check_interval)
        self._initialized = True
        logger.info(
            "ApiKeyRotator pool [%s] initialized with %d key(s) (Cooldown: %ds, Health check interval: %ds)",
            prov,
            len(keys),
            cooldown_seconds,
            health_check_interval,
        )

    def initialize_all_providers(self) -> None:
        """Initialize all provider pools from application settings."""
        settings = get_settings()

        # Groq pool
        self.initialize(
            keys=settings.groq_keys_list,
            cooldown_seconds=settings.GROQ_KEY_COOLDOWN_SECONDS,
            health_check_interval=settings.GROQ_HEALTH_CHECK_INTERVAL_SECONDS,
            provider="groq",
        )

        # Gemini pool
        self.initialize(
            keys=settings.gemini_keys_list,
            cooldown_seconds=settings.GEMINI_KEY_COOLDOWN_SECONDS,
            health_check_interval=settings.GEMINI_HEALTH_CHECK_INTERVAL_SECONDS,
            provider="gemini",
        )

        # OpenRouter pool
        self.initialize(
            keys=settings.openrouter_keys_list,
            cooldown_seconds=settings.OPENROUTER_KEY_COOLDOWN_SECONDS,
            health_check_interval=settings.OPENROUTER_HEALTH_CHECK_INTERVAL_SECONDS,
            provider="openrouter",
        )

        self._initialized = True

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize_all_providers()

    def get_configured_providers(self) -> list[str]:
        """Return list of providers that have at least one key configured, prioritizing settings order."""
        self._ensure_initialized()
        settings = get_settings()
        order = settings.llm_providers_list
        configured = [p for p in order if p in self._pools and self._pools[p].key_count > 0]
        for p, pool in self._pools.items():
            if pool.key_count > 0 and p not in configured:
                configured.append(p)
        return configured

    async def get_next_provider(self, candidates: Optional[list[str]] = None) -> Optional[str]:
        """Select preferred provider prioritizing healthy pools over downed pools."""
        self._ensure_initialized()
        pool_candidates = candidates or self.get_configured_providers()
        if not pool_candidates:
            return None

        # Prioritize the first provider in configured priority that has healthy keys
        for prov in pool_candidates:
            pool = self._pools.get(prov)
            if pool and pool.healthy_count > 0:
                return prov

        return pool_candidates[0]

    async def get_next_key(self, provider: Optional[str] = None, allow_downed: bool = False) -> tuple[Optional[str], str]:
        """Select next available API key for the requested provider."""
        self._ensure_initialized()
        prov = (provider or self._default_provider).lower()
        pool = self._pools.get(prov)
        if not pool:
            return None, "none"
        return await pool.get_next_key(allow_downed=allow_downed)

    def mark_key_down(self, key: str, reason: str, status_code: Optional[int] = None, provider: Optional[str] = None) -> None:
        """Mark an API key down in its provider pool."""
        self._ensure_initialized()
        if provider and provider.lower() in self._pools:
            self._pools[provider.lower()].mark_key_down(key, reason, status_code)
            return

        # If provider not specified, locate key across pools
        for pool in self._pools.values():
            if key in pool._keys:
                pool.mark_key_down(key, reason, status_code)
                return

    def mark_key_success(self, key: str, provider: Optional[str] = None) -> None:
        """Record successful request completion for an API key."""
        self._ensure_initialized()
        if provider and provider.lower() in self._pools:
            self._pools[provider.lower()].mark_key_success(key)
            return

        for pool in self._pools.values():
            if key in pool._keys:
                pool.mark_key_success(key)
                return

    def log_startup_summary(self) -> None:
        """Log a clean, organized startup summary of configured LLM providers and keys."""
        self._ensure_initialized()
        providers = ["groq", "gemini", "openrouter"]
        settings = get_settings()

        lines = [
            "================================================================================",
            "[CYBERGUARD LLM ENGINE] Multi-Provider Distributed AI Orchestrator",
            "--------------------------------------------------------------------------------",
        ]

        active_providers = []
        for prov in providers:
            pool = self._pools.get(prov)
            key_count = pool.key_count if pool else 0
            if prov == "groq":
                model = settings.GROQ_MODEL
            elif prov == "gemini":
                model = settings.GEMINI_MODEL
            else:
                model = settings.OPENROUTER_MODEL

            if key_count > 0:
                active_providers.append(prov)
                lines.append(f"  * {prov.upper():<12}: CONFIGURED ({key_count} active key(s) | Primary: {model})")
            else:
                lines.append(f"  * {prov.upper():<12}: NOT DEFINED (0 keys configured)")

        lines.append("--------------------------------------------------------------------------------")
        if active_providers:
            lines.append(f"  Distributed Active Pool : {active_providers}")
            lines.append("  Failover Policy         : Distributed round-robin with automatic jump & circuit breaker")
        else:
            lines.append("  [NOTICE] No API keys defined for any provider (Groq, Gemini, OpenRouter).")
            lines.append("  Server startup continues uninterrupted; explanation engine will use deterministic heuristic mode.")
        lines.append("================================================================================")

        for line in lines:
            logger.info(line)

    async def _background_loop(self) -> None:
        """Periodic background task that checks and re-releases recovered keys across all providers."""
        logger.info("Multi-Provider key health monitor background loop started")
        while self._running:
            try:
                await asyncio.sleep(30)
                now = time.time()
                for pool in self._pools.values():
                    downed_keys = [
                        s for s in pool._keys.values()
                        if not s.is_healthy and (now - s.last_failure_time >= pool._cooldown_seconds)
                    ]
                    for state in downed_keys:
                        await pool.probe_key(state)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in multi-provider key rotator background loop: %s", exc)

    def start_background_task(self) -> None:
        """Start the background recovery loop."""
        self._ensure_initialized()
        if not self._running:
            self._running = True
            self._background_task = asyncio.create_task(self._background_loop())

    def stop_background_task(self) -> None:
        """Stop the background recovery loop."""
        self._running = False
        if self._background_task and not self._background_task.done():
            self._background_task.cancel()

    def get_status(self, provider: Optional[str] = None) -> list[dict[str, Any]]:
        """Return runtime status for a specific provider or the default provider."""
        self._ensure_initialized()
        prov = (provider or self._default_provider).lower()
        pool = self._pools.get(prov)
        return pool.get_status() if pool else []

    def get_all_status(self) -> dict[str, list[dict[str, Any]]]:
        """Return runtime status for all configured providers."""
        self._ensure_initialized()
        return {prov: pool.get_status() for prov, pool in self._pools.items()}


# Global singleton instance
_rotator_instance = ApiKeyRotator()


def get_key_rotator() -> ApiKeyRotator:
    """Return the global ApiKeyRotator instance."""
    return _rotator_instance
