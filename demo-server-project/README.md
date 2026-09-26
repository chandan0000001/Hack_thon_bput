# Demo Server — Production-grade CyberGuard Gateway Client

## Architecture

- Standalone FastAPI service (port 8020) shipping realistic traffic to the CyberGuard project gateway (`POST /api/v1/p/{slug}/gateway`).
- Bearer-key auth (master key only for analysis; viewer key for future read-only endpoints).
- Persistent SQLite store (WAL mode) for every attempt (request + response + latency + error).
- Own pyproject + uv venv; deps: fastapi, uvicorn, httpx only. Zero CyberGuard backend/frontend imports — consumes the gateway exactly as verified in Part A; no backend changes.
- Retry semantics: exponential backoff (0.5s, 1s, 2s … capped 8s) on 5xx/transport errors only, at most `SHIP_MAX_RETRIES`; 4xx never retried (deterministic client errors).
- Scenario payloads live in `scenarios/` (network_critical, network_benign, ato_critical, ato_benign), each exercising a verified trigger rule (suspicious port, 10 MB exfil threshold, api rate abuse, 3-failure burst, 60-min impossible travel, success-after-failures).

## Quick Start

1. Copy `.env.example` → `.env`; set `CYBERGUARD_PROJECT_SLUG` + `CYBERGUARD_MASTER_KEY`.
2. `uv sync && uv run demo-server serve` (starts service on :8020).
3. `curl -X POST localhost:8020/traffic/start -H 'Content-Type: application/json' -d '{"rate":60,"duration":5,"mix":"net=30,ato=20,benign=50"}'`
4. `curl localhost:8020/traffic/metrics` → watch success_rate climb.

## CLI

- `ship-once payloads.json` — ship a batch (B1).
- `generate --rate 60 --duration 5` — continuous traffic (SIGINT stops gracefully after the current send).
- `responses --limit 10` — query store (B1).
- `replay --from 2026-09-26T00:00 --to 2026-09-26T23:59` — replay window (re-ships stored successful calls; new store rows, fresh event_ids).
- `serve` — start service.

## Service endpoints (port 8020)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness + gateway endpoint |
| POST | `/traffic/start` | start background generator `{rate, duration, mix, jitter}` → `{job_id}` |
| GET | `/traffic/status?job_id=…` | state (running/stopped) + events_shipped + success_rate + last_event_ts |
| POST | `/traffic/stop` | graceful stop `{job_id}` (idempotent) |
| GET | `/traffic/metrics` | last-1h `{total, by_action, by_status, by_severity, latency_ms{p50,p95}, success_rate}` |
| POST | `/traffic/replay` | re-ship window `{from_ts, to_ts}` |
| GET | `/responses?limit=&action=&min_status=` | query the store |

## Configuration (environment)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `CYBERGUARD_PROJECT_SLUG` | yes | — | project slug to ship as |
| `CYBERGUARD_MASTER_KEY` | one of the two | — | gateway key (inline) |
| `CYBERGUARD_KEY_FILE` | one of the two | — | file holding the key |
| `CYBERGUARD_GATEWAY_URL` | no | `http://localhost:8000/api/v1` | gateway base URL |
| `SHIP_TIMEOUT_S` | no | `10` | per-request timeout |
| `SHIP_MAX_RETRIES` | no | `3` | retries on 5xx/transport only |
| `DEMO_PORT` | no | `8020` | `serve` port |
| `STORE_PATH` | no | `data/responses.db` | response store path |

The key is **never logged and never written to the store** — logs carry only
endpoint, action, status, attempt number and latency; `repr(Config)` redacts
it. Missing/contradictory config fails fast with a clear error.

## Traffic mix

`--mix net=30,ato=20,benign=50` splits total rate across scenario groups
(percentages of total, must sum to 100):

- `net` → `scenarios/network_critical.json` (port 4444 C2, 12 MB+ exfil, DNS-tunneling-style request burst)
- `ato` → `scenarios/ato_critical.json` (failed-login burst, Berlin→Sydney impossible travel, credential stuffing)
- `benign` → alternates `network_benign.json` (5 shapes) and `ato_benign.json` (3 shapes)

Default mix: 70% benign / 15% net-critical / 15% ato-critical.

## Payloads

See `scenarios/` for realistic event shapes using verified trigger rules
(thresholds from `network_threat_detector` / `account_takeover_detector`):
exfil > 10 MB, suspicious ports {4444, 8888, 1337, 31337, 6667}, API rate
abuse > 50 req/min, failed burst ≥ 3, impossible travel < 60 min,
success after ≥ 2 consecutive failures.

## Tests

```bash
uv run pytest
```
