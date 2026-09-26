"""Gateway shipper: POSTs analysis requests to the CyberGuard project gateway.

Retry policy (per config SHIP_MAX_RETRIES):
  - retry ONLY on 5xx responses and transport errors (connection refused,
    timeouts, DNS failures), with exponential backoff
  - NEVER retry on 4xx (client errors are deterministic — a retry would
    just burn quota; e.g. a viewer key always gets 403)

Every attempt is appended to the response store. The Bearer key is attached
here and is never logged or stored: logs carry only endpoint, action,
status, attempt number and latency.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import Config
from .store import TRANSPORT_ERROR, ResponseStore

logger = logging.getLogger("demo_server.shipper")

# Backoff base for retry sleeps, seconds: 0.5, 1, 2, ... capped at 8.
BACKOFF_BASE_S = 0.5
BACKOFF_CAP_S = 8.0


@dataclass
class ShipResult:
    action: str
    ok: bool
    attempts: int
    status: str | None = None  # last HTTP status as str, or None for transport errors
    response: dict[str, Any] | None = None
    error: str | None = None
    attempt_statuses: list[str] = field(default_factory=list)


class GatewayShipper:
    def __init__(
        self,
        config: Config,
        store: ResponseStore,
        client: httpx.Client | None = None,
        sleeper: Any = time.sleep,
    ) -> None:
        """`client` and `sleeper` are injectable for tests (mock transport,
        no real sleeping); production builds use a real httpx.Client."""
        self.config = config
        self.store = store
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=config.ship_timeout_s)
        self._sleep = sleeper

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def ship(self, action: str, payload: Any) -> ShipResult:
        """Ship one analysis request: {action, data: payload}. Retries on
        5xx/transport only. Every attempt is stored."""
        max_retries = self.config.ship_max_retries
        endpoint = self.config.gateway_endpoint
        result = ShipResult(action=action, ok=False, attempts=0)

        for attempt in range(1, max_retries + 2):
            result.attempts = attempt
            started = time.monotonic()
            status: str | None = None
            response_body: Any = None
            error: str | None = None
            retryable = False

            try:
                resp = self.client.post(
                    endpoint,
                    headers={
                        "Authorization": f"Bearer {self.config.master_key}",
                        "Content-Type": "application/json",
                    },
                    json={"action": action, "data": payload},
                )
                elapsed_ms = int((time.monotonic() - started) * 1000)
                status = str(resp.status_code)
                try:
                    response_body = resp.json()
                except ValueError:
                    response_body = resp.text[:2000]
                if resp.status_code >= 500:
                    retryable = True
                    error = f"HTTP {resp.status_code}"
            except httpx.HTTPError as exc:
                elapsed_ms = int((time.monotonic() - started) * 1000)
                status = TRANSPORT_ERROR
                retryable = True
                error = f"{type(exc).__name__}: {exc}"

            result.attempt_statuses.append(status or TRANSPORT_ERROR)
            self.store.append(
                action=action,
                request={"action": action, "data": payload},
                status=status or TRANSPORT_ERROR,
                response=response_body if status is not None and status != TRANSPORT_ERROR else None,
                latency_ms=elapsed_ms,
                error=error,
            )
            logger.info(
                "gateway call action=%s attempt=%d/%d status=%s latency_ms=%d endpoint=%s",
                action,
                attempt,
                max_retries + 1,
                status,
                elapsed_ms,
                endpoint,
            )

            if status is not None and status != TRANSPORT_ERROR:
                result.status = status
                result.response = response_body
                if resp.status_code < 400:
                    result.ok = True
                    break
                if not retryable or attempt > max_retries:
                    break
                result.error = error
            else:
                result.error = error
                if attempt > max_retries:
                    break
            self._sleep(min(BACKOFF_BASE_S * (2 ** (attempt - 1)), BACKOFF_CAP_S))

        return result
