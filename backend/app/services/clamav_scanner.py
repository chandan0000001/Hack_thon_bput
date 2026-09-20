"""ClamAV engine — optional daemon-based antivirus scanning.

ClamAV runs as a separate clamd daemon (TCP 3310). It is deliberately
OPTIONAL: if the daemon is not running, the scanner reports itself
unavailable and the attachment pipeline continues without it (graceful
fallback). An AV outage must never block the mail pipeline, and a missing
daemon must never crash it.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("cyberguard.attachment.clamav")


class ClamAVScanner:
    """Scans files through a clamd daemon; degrades gracefully when absent."""

    def __init__(self, host: str = "127.0.0.1", port: int = 3310, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._clamd = None
        self.available = self._check_daemon()

    def _check_daemon(self) -> bool:
        """Ping clamd with a short 2s budget; False on any failure."""
        try:
            import pyclamd

            client = pyclamd.ClamdNetworkSocket(self.host, self.port, timeout=2)
            client.ping()
            self._clamd = pyclamd.ClamdNetworkSocket(self.host, self.port, timeout=self.timeout)
            return True
        except Exception as exc:
            logger.info("ClamAV daemon unavailable at %s:%s (%s); continuing without AV", self.host, self.port, exc)
            return False

    def scan_file(self, file_path: str) -> dict:
        """Scan one file. Returns {engine, available, status, signature, risk_score}.

        status: "clean" | "infected" | "error" | "unavailable".
        AV outage (socket/timeout) maps to status "error" with risk_score 0 —
        scanning never blocks the pipeline on engine availability.
        """
        if not self.available or self._clamd is None:
            return {
                "engine": "clamav",
                "available": False,
                "status": "unavailable",
                "signature": None,
                "risk_score": 0,
            }

        try:
            result = self._clamd.scan_file(file_path)
        except Exception as exc:
            logger.warning("ClamAV scan failed for %s: %s", file_path, exc)
            return {
                "engine": "clamav",
                "available": True,
                "status": "error",
                "signature": None,
                "risk_score": 0,
            }

        # pyclamd returns {file_path: ("OK", None) | ("FOUND", signature) | ("ERROR", message)}
        status_raw: tuple[str, Optional[str]] = next(iter(result.values()), ("ERROR", "empty response"))
        raw_status, signature = status_raw[0], status_raw[1]

        if raw_status == "FOUND":
            return {
                "engine": "clamav",
                "available": True,
                "status": "infected",
                "signature": signature,
                "risk_score": 90,
            }
        if raw_status == "OK":
            return {
                "engine": "clamav",
                "available": True,
                "status": "clean",
                "signature": None,
                "risk_score": 0,
            }
        return {
            "engine": "clamav",
            "available": True,
            "status": "error",
            "signature": signature,
            "risk_score": 0,
        }
