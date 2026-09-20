"""Pure-ASGI middleware that binds the client IP to log context and emits one
clean per-request line (method, path, status, duration, IP) for api.log."""

from __future__ import annotations

import logging
import time
from typing import Any

from app.core.logging_config import set_client_ip

request_logger = logging.getLogger("cyberguard.api.request")


class ClientContextMiddleware:
    """Bind client IP for every HTTP request and log a single request line.

    Pure ASGI (not BaseHTTPMiddleware) so the contextvar set here is visible
    to endpoint code running downstream in the same task.
    """

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        forwarded = headers.get("x-forwarded-for")
        ip = forwarded.split(",")[0].strip() if forwarded else None
        ip = ip or headers.get("x-real-ip") or (scope.get("client") or (None,))[0] or "unknown"

        token = set_client_ip(ip)
        started = time.perf_counter()
        status_holder: dict[str, int] = {"status": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            path = scope.get("path", "")
            if not path.endswith(("/health", "/ready", "/metrics")):
                request_logger.info(
                    "API %s %s -> %s in %.0f ms",
                    scope.get("method", "-"),
                    path,
                    status_holder["status"],
                    elapsed_ms,
                )
