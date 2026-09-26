"""Continuous traffic generator.

Ships scenario payloads at a configurable rate with jitter via the B1
shipper (which stores every attempt). Runs as a blocking loop suitable for
a CLI or a background thread; stop cooperatively via `threading.Event`
(SIGINT in the CLI sets the event, the loop finishes the current send and
returns a summary).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .scenarios import ScenarioBook, Template
from .shipper import GatewayShipper, ShipResult

Clock = Callable[[], float]


@dataclass
class TrafficSummary:
    events_shipped: int = 0
    succeeded: int = 0
    failed: int = 0
    stopped_early: bool = False
    started_at: str | None = None
    finished_at: str | None = None
    elapsed_s: float = 0.0
    by_action: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    last_event_ts: str | None = None

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.events_shipped if self.events_shipped else 0.0

    def as_dict(self) -> dict:
        return {
            "events_shipped": self.events_shipped,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "success_rate": round(self.success_rate, 4),
            "stopped_early": self.stopped_early,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_s": round(self.elapsed_s, 3),
            "by_action": self.by_action,
            "by_category": self.by_category,
            "last_event_ts": self.last_event_ts,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate(
    shipper: GatewayShipper,
    book: ScenarioBook,
    mix: dict[str, float],
    rate_per_min: float = 60,
    duration_min: float = 10,
    jitter: float = 0.2,
    stop_event: threading.Event | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    now_fn: Clock = time.monotonic,
    on_ship: Callable[[Template, ShipResult], None] | None = None,
) -> TrafficSummary:
    """Ship `rate_per_min * duration_min` payloads spread over the window.

    The base interval is 60/rate seconds, multiplied by
    (1 + uniform(-jitter, +jitter)). `stop_event` ends the loop after the
    current send completes (graceful). `sleeper`/`now_fn` are injectable
    for tests.
    """
    if rate_per_min <= 0:
        raise ValueError("rate_per_min must be > 0")
    if duration_min <= 0:
        raise ValueError("duration_min must be > 0")
    if not 0 <= jitter < 1:
        raise ValueError("jitter must be in [0, 1)")
    if not mix:
        raise ValueError("mix must select at least one group")
    total_weight = sum(mix.values())
    if total_weight <= 0:
        raise ValueError("mix weights must sum to > 0")

    import random

    rng = book.rng
    stop_event = stop_event or threading.Event()
    summary = TrafficSummary(started_at=_now_iso())

    total_sends = max(1, round(rate_per_min * duration_min))
    base_interval = 60.0 / rate_per_min
    started = now_fn()

    for i in range(total_sends):
        if stop_event.is_set():
            summary.stopped_early = True
            break

        # weighted group pick
        roll = rng.random() * total_weight
        acc = 0.0
        group = next(iter(mix))
        for g, weight in mix.items():
            acc += weight
            if roll <= acc:
                group = g
                break

        template = book.pick(group)
        result = shipper.ship(template.action, template.data)

        summary.events_shipped += 1
        summary.by_action[template.action] = summary.by_action.get(template.action, 0) + 1
        summary.by_category[template.category] = summary.by_category.get(template.category, 0) + 1
        if result.ok:
            summary.succeeded += 1
        else:
            summary.failed += 1
        summary.last_event_ts = _now_iso()
        if on_ship is not None:
            on_ship(template, result)

        if i < total_sends - 1 and not stop_event.is_set():
            delay = base_interval * (1 + rng.uniform(-jitter, jitter))
            sleeper(max(0.0, delay))
            if stop_event.is_set():
                # woke up early because stop was requested: don't send again
                summary.stopped_early = True
                break

    summary.finished_at = _now_iso()
    summary.elapsed_s = now_fn() - started
    return summary
