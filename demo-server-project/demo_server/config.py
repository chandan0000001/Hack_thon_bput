"""Fail-fast configuration for the CyberGuard gateway client.

Every value comes from the environment. Missing/contradictory required
values raise ConfigError with a clear message at startup — never lazily
mid-shipment. The API key is held in memory only: it is never logged,
never written to the response store, and `repr()`/`str()` of this module's
objects redact it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when configuration is missing or contradictory."""


GATEWAY_URL_DEFAULT = "http://localhost:8000/api/v1"
SHIP_TIMEOUT_S_DEFAULT = 10
SHIP_MAX_RETRIES_DEFAULT = 3
DEMO_PORT_DEFAULT = 8020
STORE_PATH_DEFAULT = "data/responses.db"

REDACTED = "***REDACTED***"


@dataclass(frozen=True)
class Config:
    gateway_url: str
    project_slug: str
    master_key: str = field(repr=False)
    ship_timeout_s: int
    ship_max_retries: int
    demo_port: int
    store_path: str

    def __post_init__(self) -> None:
        if not self.master_key:
            raise ConfigError("master_key must be a non-empty string")

    @property
    def gateway_endpoint(self) -> str:
        """Full gateway URL this client ships to: {url}/p/{slug}/gateway."""
        return f"{self.gateway_url.rstrip('/')}/p/{self.project_slug}/gateway"

    def describe(self) -> dict[str, object]:
        """Log-safe view of the config (key redacted)."""
        return {
            "gateway_url": self.gateway_url,
            "project_slug": self.project_slug,
            "gateway_endpoint": self.gateway_endpoint,
            "master_key": REDACTED,
            "ship_timeout_s": self.ship_timeout_s,
            "ship_max_retries": self.ship_max_retries,
            "demo_port": self.demo_port,
            "store_path": self.store_path,
        }


def load_config(env: dict[str, str] | None = None) -> Config:
    """Build a Config from environment variables, failing fast.

    Required:
      CYBERGUARD_PROJECT_SLUG                     project slug to ship as
      CYBERGUARD_MASTER_KEY or CYBERGUARD_KEY_FILE   gateway key (exactly one)
    Optional:
      CYBERGUARD_GATEWAY_URL  (default http://localhost:8000/api/v1)
      SHIP_TIMEOUT_S          (default 10)
      SHIP_MAX_RETRIES        (default 3)
      DEMO_PORT               (default 8020)
      STORE_PATH              (default data/responses.db)
    """
    src = dict(os.environ) if env is None else env

    slug = src.get("CYBERGUARD_PROJECT_SLUG", "").strip()
    if not slug:
        raise ConfigError(
            "CYBERGUARD_PROJECT_SLUG is required (slug of the CyberGuard project to ship as)"
        )

    direct_key = src.get("CYBERGUARD_MASTER_KEY", "").strip()
    key_file = src.get("CYBERGUARD_KEY_FILE", "").strip()
    if direct_key and key_file:
        raise ConfigError(
            "Set only one of CYBERGUARD_MASTER_KEY or CYBERGUARD_KEY_FILE, not both"
        )
    if not direct_key and not key_file:
        raise ConfigError(
            "A gateway key is required: set CYBERGUARD_MASTER_KEY "
            "(inline) or CYBERGUARD_KEY_FILE (path to a file holding the key)"
        )

    if key_file:
        key_path = Path(key_file).expanduser()
        if not key_path.is_file():
            raise ConfigError(f"CYBERGUARD_KEY_FILE does not exist: {key_path}")
        try:
            master_key = key_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"CYBERGUARD_KEY_FILE unreadable: {exc}") from exc
        if not master_key:
            raise ConfigError(f"CYBERGUARD_KEY_FILE is empty: {key_path}")
    else:
        master_key = direct_key

    return Config(
        gateway_url=src.get("CYBERGUARD_GATEWAY_URL", "").strip() or GATEWAY_URL_DEFAULT,
        project_slug=slug,
        master_key=master_key,
        ship_timeout_s=_int_var(src, "SHIP_TIMEOUT_S", SHIP_TIMEOUT_S_DEFAULT),
        ship_max_retries=_int_var(src, "SHIP_MAX_RETRIES", SHIP_MAX_RETRIES_DEFAULT),
        demo_port=_int_var(src, "DEMO_PORT", DEMO_PORT_DEFAULT),
        store_path=src.get("STORE_PATH", "").strip() or STORE_PATH_DEFAULT,
    )


def _int_var(src: dict[str, str], name: str, default: int) -> int:
    raw = src.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got: {raw!r}") from exc
