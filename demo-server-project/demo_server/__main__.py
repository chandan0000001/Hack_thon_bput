"""CLI entrypoint: python -m demo_server {ship-once,responses,counts,serve}

B1 scope: `serve` exposes a health endpoint only; traffic generation
arrives in B2.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from .config import Config, ConfigError, load_config
from .shipper import GatewayShipper, ShipResult
from .store import ResponseStore


def build_components(env: dict[str, str] | None = None) -> tuple[Config, ResponseStore, GatewayShipper]:
    """Wire config + store + shipper (tests monkeypatch the httpx client via
    GatewayShipper's injection point; production uses defaults)."""
    config = load_config(env)
    store = ResponseStore(config.store_path)
    shipper = GatewayShipper(config, store)
    return config, store, shipper


def _print_ship_table(results: list[ShipResult]) -> None:
    headers = ["ACTION", "ATTEMPTS", "STATUS", "SEVERITY", "VERDICT/RISK", "ERROR"]
    rows: list[list[str]] = []
    for r in results:
        severity = risk = ""
        if isinstance(r.response, dict):
            severity = str(r.response.get("severity", ""))
            risk = f"{r.response.get('verdict', '')} / {r.response.get('risk_score', '')}"
        rows.append(
            [
                r.action,
                str(r.attempts),
                r.status or "transport_error",
                severity,
                risk,
                (r.error or "")[:60],
            ]
        )
    widths = [max(len(h), *(len(row[i]) for row in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("-" * len(line))
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))


def _load_payload_file(path: str) -> list[dict[str, Any]]:
    """Accepted formats:
    - list of {"action": ..., "data": ...} (optional "name")
    - {"<action>": <data>, ...} mapping
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or "action" not in item:
                raise ValueError(f"payload list entries must be objects with an 'action' key: {item!r}")
            entries.append(item)
    elif isinstance(raw, dict):
        for action, data in raw.items():
            entries.append({"action": action, "data": data})
    else:
        raise ValueError("payload file must be a JSON list or object")
    return entries


def cmd_ship_once(args: argparse.Namespace) -> int:
    entries = _load_payload_file(args.file)
    config, _store, shipper = build_components()
    results = []
    exit_code = 0
    for entry in entries:
        result = shipper.ship(entry["action"], entry.get("data"))
        results.append(result)
        if not result.ok:
            exit_code = 1
    shipper.close()
    _print_ship_table(results)
    return exit_code


def cmd_responses(args: argparse.Namespace) -> int:
    config = load_config()
    store = ResponseStore(config.store_path)
    rows = store.query(limit=args.limit, action=args.action, min_status=args.min_status)
    headers = ["ID", "TS", "ACTION", "STATUS", "LAT_MS", "RESPONSE (truncated)", "ERROR"]
    rows_out = []
    for r in rows:
        rows_out.append(
            [
                str(r["id"]),
                str(r["ts"]),
                str(r["action"]),
                str(r["status"]),
                str(r["latency_ms"] if r["latency_ms"] is not None else ""),
                (r["response_json"] or "")[:80],
                (r["error"] or "")[:60],
            ]
        )
    widths = [
        max(len(h), *(len(row[i]) for row in rows_out)) if rows_out else len(h)
        for i, h in enumerate(headers)
    ]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for row in rows_out:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))
    return 0


def cmd_counts(_args: argparse.Namespace) -> int:
    config = load_config()
    store = ResponseStore(config.store_path)
    counts = store.counts()
    print(f"total attempts: {counts.get('total', 0)}")
    for status, n in sorted(counts.items()):
        if status != "total":
            print(f"  status {status}: {n}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """B1: health-only FastAPI app (B2 adds traffic generation)."""
    import uvicorn
    from fastapi import FastAPI

    from . import __version__

    config = load_config()

    app = FastAPI(title="CyberGuard Demo Server", version=__version__)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "demo-server",
            "version": __version__,
            "gateway_endpoint": config.gateway_endpoint,
            "project_slug": config.project_slug,
        }

    uvicorn.run(app, host="127.0.0.1", port=args.port or config.demo_port, log_level="info")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(prog="demo_server", description="CyberGuard gateway demo client")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ship-once", help="ship each payload from a JSON file once")
    p.add_argument("--file", required=True, help="path to payloads JSON")
    p.set_defaults(func=cmd_ship_once)

    p = sub.add_parser("responses", help="list stored gateway attempts")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--action", default=None)
    p.add_argument("--min-status", dest="min_status", type=int, default=None)
    p.set_defaults(func=cmd_responses)

    sub.add_parser("counts", help="attempt counts by status").set_defaults(func=cmd_counts)

    p = sub.add_parser("serve", help="run the demo server (health endpoint; B2 adds traffic)")
    p.add_argument("--port", type=int, default=None, help="override DEMO_PORT")
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
