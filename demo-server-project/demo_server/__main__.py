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
    """Start the demo service (health, traffic control, metrics, replay)."""
    import uvicorn

    from .service import create_app

    config = load_config()
    app = create_app(config)
    uvicorn.run(app, host="127.0.0.1", port=args.port or config.demo_port, log_level="info")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    """Run the traffic generator in the foreground; SIGINT stops gracefully."""
    import signal
    import threading

    from .scenarios import ScenarioBook, ScenarioError, parse_mix
    from .traffic import generate

    try:
        mix = parse_mix(args.mix)
    except ScenarioError as exc:
        print(f"mix error: {exc}", file=sys.stderr)
        return 2

    config, _store, shipper = build_components()
    book = ScenarioBook()
    stop_event = threading.Event()

    def _sigint(signum: int, _frame: Any) -> None:
        print("\nSIGINT received — finishing current send, stopping schedule...")
        stop_event.set()

    prev_handler = signal.signal(signal.SIGINT, _sigint)
    try:
        summary = generate(
            shipper,
            book,
            mix,
            rate_per_min=args.rate,
            duration_min=args.duration,
            jitter=args.jitter,
            stop_event=stop_event,
        )
    finally:
        signal.signal(signal.SIGINT, prev_handler)
        shipper.close()

    print(f"\nevents shipped : {summary.events_shipped}")
    print(f"succeeded      : {summary.succeeded}")
    print(f"failed         : {summary.failed}")
    print(f"success rate   : {summary.success_rate:.2%}")
    print(f"stopped early  : {summary.stopped_early}")
    print(f"elapsed s      : {summary.elapsed_s:.1f}")
    print(f"by category    : {summary.by_category}")
    return 0 if summary.failed == 0 else 1


def cmd_replay(args: argparse.Namespace) -> int:
    """Re-ship stored successful calls in a time window."""
    from .replay import ReplayError, replay

    config, store, shipper = build_components()
    try:
        stats = replay(shipper, store, args.from_ts, args.to_ts, max_rows=args.max_rows)
    except ReplayError as exc:
        print(f"replay error: {exc}", file=sys.stderr)
        return 2
    finally:
        shipper.close()

    print(f"window         : {stats['window']['from']} -> {stats['window']['to']}")
    print(f"replayed       : {stats['replayed']}")
    print(f"succeeded      : {stats['succeeded']}")
    print(f"success rate   : {stats['success_rate']:.2%}")
    print(f"sample old ids : {stats['old_event_ids'][:3]}")
    print(f"sample new ids : {stats['new_event_ids'][:3]}")
    return 0 if stats["replayed"] == stats["succeeded"] else 1


def cmd_campaign_run(args: argparse.Namespace) -> int:
    """Run an attack campaign with stage progression and verdict assertions."""
    from .campaign import format_campaign_table, get_campaign, run_campaign

    try:
        camp = get_campaign(args.name)
    except KeyError as exc:
        print(f"campaign error: {exc}", file=sys.stderr)
        return 2

    config, _store, shipper = build_components()
    try:
        summary = run_campaign(
            shipper,
            camp,
            timescale=args.timescale,
            attacker_ip=args.attacker_ip,
        )
    finally:
        shipper.close()

    print(format_campaign_table(summary))
    return 0 if summary.failed == 0 else 1


def cmd_campaign_report(args: argparse.Namespace) -> int:
    """Display gateway calls and closed-loop auto-enforcement report."""
    config, store, shipper = build_components()
    try:
        rows = store.query(limit=args.limit)
    finally:
        shipper.close()

    print(f"Response store report ({len(rows)} recent calls from {config.store_path}):\n")

    headers = ["ID", "TS", "ACTION", "STATUS", "SEVERITY", "VERDICT", "BLOCKED_MATCH", "LAT_MS"]
    rows_out = []
    for r in rows:
        resp = {}
        if r.get("response_json"):
            try:
                resp = json.loads(r["response_json"])
            except Exception:
                pass
        severity = resp.get("severity", "") if isinstance(resp, dict) else ""
        verdict = resp.get("verdict", "") if isinstance(resp, dict) else ""
        matched = "TRUE" if isinstance(resp, dict) and resp.get("blocked_indicator_matched") else "false"
        rows_out.append([
            str(r["id"]),
            str(r["ts"]),
            str(r["action"]),
            str(r["status"]),
            severity,
            verdict,
            matched,
            str(r["latency_ms"] if r["latency_ms"] is not None else ""),
        ])
    widths = [max(len(h), *(len(row[i]) for row in rows_out)) if rows_out else len(h) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for row in rows_out:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))
    return 0


def cmd_campaign_list(_args: argparse.Namespace) -> int:
    """List all available attack campaigns and stages."""
    from .campaign import CAMPAIGNS

    print("Available Attack Campaigns:\n")
    for name, camp in sorted(CAMPAIGNS.items()):
        print(f"  • {name}: {camp.description}")
        print(f"    Stages ({len(camp.stages)}):")
        for s in camp.stages:
            print(f"      - {s.name}: action={s.action}, expected_severity={s.expected_severity}, delay={s.delay_s}s")
        print()
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

    p = sub.add_parser("generate", help="run continuous traffic (SIGINT stops gracefully)")
    p.add_argument("--rate", type=float, default=60.0, help="payloads per minute")
    p.add_argument("--duration", type=float, default=10.0, help="minutes to run")
    p.add_argument("--mix", default="net=15,ato=15,benign=70",
                   help="percent split, e.g. net=30,ato=20,benign=50")
    p.add_argument("--jitter", type=float, default=0.2, help="interval jitter 0..1")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("replay", help="re-ship stored successful calls in a time window")
    p.add_argument("--from", dest="from_ts", required=True, help="window start (ISO, UTC)")
    p.add_argument("--to", dest="to_ts", required=True, help="window end (ISO, UTC)")
    p.add_argument("--max-rows", dest="max_rows", type=int, default=1000)
    p.set_defaults(func=cmd_replay)

    sub.add_parser("counts", help="attempt counts by status").set_defaults(func=cmd_counts)

    p = sub.add_parser("serve", help="run the demo server (health endpoint; B2 adds traffic)")
    p.add_argument("--port", type=int, default=None, help="override DEMO_PORT")
    p.set_defaults(func=cmd_serve)

    p_camp = sub.add_parser("campaign", help="execute and report multi-stage attack campaigns")
    camp_sub = p_camp.add_subparsers(dest="campaign_cmd", required=True)

    p_crun = camp_sub.add_parser("run", help="run attack campaign")
    p_crun.add_argument("--name", required=True, help="campaign name: cred_stuffing, exfil_spike, c2_beacon_wave")
    p_crun.add_argument("--timescale", type=float, default=1.0, help="delay timescale (default 1.0)")
    p_crun.add_argument("--attacker-ip", default=None, help="attacker IP override")
    p_crun.set_defaults(func=cmd_campaign_run)

    p_crep = camp_sub.add_parser("report", help="display gateway calls and verdict report")
    p_crep.add_argument("--limit", type=int, default=20, help="limit results")
    p_crep.set_defaults(func=cmd_campaign_report)

    p_clist = camp_sub.add_parser("list", help="list available campaigns")
    p_clist.set_defaults(func=cmd_campaign_list)

    args = parser.parse_args(argv)
    try:
        return args.func(args)

    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
