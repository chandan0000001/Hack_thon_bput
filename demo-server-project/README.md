# demo-server-project

Standalone, production-grade client for the CyberGuard **project gateway**
(`POST /api/v1/p/{slug}/gateway`). Lives in the main repo tree but is fully
self-contained: own `pyproject.toml`, own uv venv, zero CyberGuard
backend/frontend imports. It consumes the gateway exactly as verified in
Part A — no backend changes.

## Layout

```
demo-server-project/
├── demo_server/
│   ├── __init__.py
│   ├── __main__.py    # CLI: ship-once | responses | counts | serve
│   ├── config.py      # fail-fast env config (key never logged/stored)
│   ├── shipper.py     # POST {url}/p/{slug}/gateway, retry 5xx/transport only
│   └── store.py       # sqlite3 WAL log of every attempt
├── tests/             # pytest suite
├── data/              # runtime store (gitignored)
└── payloads.example.json
```

## Setup

```bash
cd demo-server-project
uv sync            # creates .venv with fastapi, uvicorn, httpx (+ pytest)
```

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

## CLI

```bash
export CYBERGUARD_PROJECT_SLUG=demo
export CYBERGUARD_MASTER_KEY=cg_org_...

uv run python -m demo_server ship-once --file payloads.example.json
uv run python -m demo_server responses --limit 10 --action analyze_network
uv run python -m demo_server counts
uv run python -m demo_server serve        # health endpoint: GET /health (B1; B2 adds traffic)
```

## Retry semantics

- **5xx / transport errors** → retried with exponential backoff
  (0.5s, 1s, 2s … capped at 8s), at most `SHIP_MAX_RETRIES` retries.
- **4xx** → never retried (deterministic client error; e.g. a viewer key
  always gets 403).
- **Every attempt** (success, HTTP error, transport failure) is appended to
  the store with status, response, latency and error.

## Tests

```bash
uv run pytest
```
