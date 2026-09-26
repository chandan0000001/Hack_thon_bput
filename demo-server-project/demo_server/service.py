"""FastAPI service (port 8020): traffic control, metrics, replay, store API.

App factory takes optional config/store/shipper so tests can inject a
MockTransport-backed shipper. The traffic generator runs in a background
thread with cooperative stop (threading.Event), so POST /traffic/stop is
graceful: the current send completes, no new sends are scheduled.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from . import __version__, metrics as metrics_mod
from .config import Config, load_config
from .replay import ReplayError, replay as run_replay
from .scenarios import MIX_GROUPS, ScenarioBook, ScenarioError, parse_mix
from .shipper import GatewayShipper
from .store import ResponseStore
from .traffic import TrafficSummary, generate

logger = logging.getLogger("demo_server.service")


class TrafficStartRequest(BaseModel):
    rate: float = Field(60, gt=0, description="payloads per minute")
    duration: float = Field(10, gt=0, description="minutes to run")
    mix: str = Field("net=15,ato=15,benign=70", description="percentages, e.g. net=30,ato=20,benign=50")
    jitter: float = Field(0.2, ge=0, lt=1)


class JobRefRequest(BaseModel):
    job_id: str


class ReplayRequest(BaseModel):
    from_ts: str
    to_ts: str
    max_rows: int = Field(1000, gt=0)


class TrafficJob:
    def __init__(self, job_id: str, rate: float, duration: float, mix_raw: str) -> None:
        self.id = job_id
        self.rate = rate
        self.duration = duration
        self.mix_raw = mix_raw
        self.state = "running"
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.summary = TrafficSummary()
        self.thread: threading.Thread | None = None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            s = self.summary
            return {
                "job_id": self.id,
                "state": self.state,
                "rate_per_min": self.rate,
                "duration_min": self.duration,
                "mix": self.mix_raw,
                "events_shipped": s.events_shipped,
                "succeeded": s.succeeded,
                "failed": s.failed,
                "success_rate": round(s.success_rate, 4),
                "last_event_ts": s.last_event_ts,
                "started_at": s.started_at,
                "finished_at": s.finished_at,
                "elapsed_s": round(s.elapsed_s, 3),
                "by_action": dict(s.by_action),
                "by_category": dict(s.by_category),
            }


def _on_ship(job: TrafficJob) -> Any:
    def hook(_template, _result) -> None:
        with job.lock:
            job.summary.events_shipped += 1
            if _result.ok:
                job.summary.succeeded += 1
            else:
                job.summary.failed += 1
            job.summary.by_action[_template.action] = (
                job.summary.by_action.get(_template.action, 0) + 1
            )
            job.summary.by_category[_template.category] = (
                job.summary.by_category.get(_template.category, 0) + 1
            )
            job.summary.last_event_ts = datetime.now(timezone.utc).isoformat()

    return hook


def _job_main(job: TrafficJob, config: Config, store: ResponseStore, shipper: GatewayShipper, book: ScenarioBook, mix: dict[str, float]) -> None:
    try:
        summary = generate(
            shipper,
            book,
            mix,
            rate_per_min=job.rate,
            duration_min=job.duration,
            jitter=0.2,
            stop_event=job.stop_event,
            on_ship=_on_ship(job),
        )
        with job.lock:
            job.summary = summary
            job.state = "stopped"  # covers both natural completion and stop request
        logger.info(
            "traffic job %s finished: shipped=%d succeeded=%d stopped_early=%s",
            job.id, summary.events_shipped, summary.succeeded, summary.stopped_early,
        )
    except Exception:
        with job.lock:
            job.state = "stopped"
        logger.exception("traffic job %s crashed", job.id)


def create_app(
    config: Config | None = None,
    store: ResponseStore | None = None,
    shipper: GatewayShipper | None = None,
    book: ScenarioBook | None = None,
) -> FastAPI:
    cfg = config or load_config()
    owned_store = store is None
    st = store or ResponseStore(cfg.store_path)
    sp = shipper or GatewayShipper(cfg, st)
    bk = book or ScenarioBook()
    jobs: dict[str, TrafficJob] = {}
    jobs_lock = threading.Lock()

    app = FastAPI(title="CyberGuard Demo Server", version=__version__)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "demo-server",
            "version": __version__,
            "gateway_endpoint": cfg.gateway_endpoint,
            "project_slug": cfg.project_slug,
        }

    @app.post("/traffic/start")
    def traffic_start(req: TrafficStartRequest) -> dict[str, Any]:
        try:
            mix = parse_mix(req.mix)
            for group in mix:
                bk.categories_for_group(group)  # validate group names early
        except ScenarioError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        job = TrafficJob(str(uuid.uuid4()), req.rate, req.duration, req.mix)
        thread = threading.Thread(
            target=_job_main,
            args=(job, cfg, st, sp, bk, mix),
            name=f"traffic-{job.id[:8]}",
            daemon=True,
        )
        with jobs_lock:
            jobs[job.id] = job
        job.thread = thread
        thread.start()
        snap = job.snapshot()
        return {"job_id": job.id, "state": snap["state"], "rate_per_min": req.rate,
                "duration_min": req.duration, "mix": req.mix}

    def _get_job(job_id: str) -> TrafficJob:
        with jobs_lock:
            job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail=f"unknown job_id: {job_id}")
        return job

    @app.get("/traffic/status")
    def traffic_status(job_id: str = Query(...)) -> dict[str, Any]:
        return _get_job(job_id).snapshot()

    @app.post("/traffic/stop")
    def traffic_stop(req: JobRefRequest) -> dict[str, Any]:
        job = _get_job(req.job_id)
        job.stop_event.set()  # idempotent; thread finishes current send
        return {"job_id": job.id, "state": job.state, "stopped": True}

    @app.get("/traffic/metrics")
    def traffic_metrics(window_min: int = Query(60, gt=0, le=1440)) -> dict[str, Any]:
        return metrics_mod.compute(st, window_minutes=window_min)

    @app.post("/traffic/replay")
    def traffic_replay(req: ReplayRequest) -> dict[str, Any]:
        try:
            return run_replay(sp, st, req.from_ts, req.to_ts, max_rows=req.max_rows)
        except ReplayError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/responses")
    def responses(
        limit: int = Query(20, gt=0, le=500),
        action: str | None = Query(None),
        min_status: int | None = Query(None, ge=100, le=599),
    ) -> dict[str, Any]:
        rows = st.query(limit=limit, action=action, min_status=min_status)
        return {"count": len(rows), "rows": rows}

    return app
