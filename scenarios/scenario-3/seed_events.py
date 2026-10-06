#!/usr/bin/env python3
"""CYBERGUARD — Scenario 3: seed dummy ATO events for the List -> Detail UI.

Authenticates with the org MASTER_API_KEY from backend/.env (no bypasses:
the server resolves the org/project scope from that credential) and POSTs
four analysis requests covering the 3-tier enforcement bands:

  1. SAFE      (score < 30)          -> ALLOWED            (normal Monday login)
  2. MEDIUM    (30 <= score < 75)    -> USER_NOTIFIED      (odd-hour login from a
                                                        new device abroad)
  3. CRITICAL  (score >= 75)         -> ACCOUNT_RESTRICTED (the full 5-stage
                                                        attack timeline, 92/100)
  4. CRITICAL  (score >= 75)         -> ACCOUNT_RESTRICTED (login from a
                                                        watchlist IP, capped 100)

Then lists GET /analysis/account-takeover/events so the judge's list view
is never empty. Idempotent: re-running seeds another batch (the UI lists
the most recent first), which is fine for a demo.

Usage:
  uv run --project backend python scenarios/scenario-3/seed_events.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from simulate import ENV_FILE, REPO_ROOT, load_env  # noqa: E402

from simulate import ApiClient, api_error  # noqa: E402

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN = "\033[31m", "\033[32m", "\033[33m", "\033[36m"

BASELINE_TEMPLATE = {
    "role": "Finance Director",
    "typical_login_start": "09:00",
    "typical_login_end": "10:00",
    "home_country": "US",
    "known_ips": ["98.42.117.6", "10.0.4.15"],
    "known_devices": ["MAC-BOOK-A7F3", "IPHONE-12-SARAH"],
}


def baseline_for(account_id: str) -> dict:
    baseline = dict(BASELINE_TEMPLATE)
    baseline["user"] = account_id
    return baseline

SEEDS = [
    {
        "name": "SAFE — normal working hours",
        "account_id": "sarah.chen@acme.com",
        "timeline": [
            {
                "timestamp": "2026-10-06T09:20:00",
                "event_type": "login_success",
                "source_ip": "98.42.117.6",
                "country": "US",
                "device_id": "MAC-BOOK-A7F3",
                "detail": "Regular morning login from the office IP",
            },
            {
                "timestamp": "2026-10-06T09:40:00",
                "event_type": "file_access",
                "files_accessed": 12,
                "detail": "Routine file access",
            },
        ],
    },
    {
        "name": "MEDIUM — odd-hour login from a new device abroad",
        "account_id": "john.doe@acme.com",
        "timeline": [
            {
                "timestamp": "2026-10-06T03:30:00",
                "event_type": "login_success",
                "source_ip": "198.51.100.9",
                "country": "CA",
                "device_id": "WIN-NEW-BOX",
                "detail": "Late-night login from an unfamiliar device in CA",
            }
        ],
    },
    {
        "name": "CRITICAL — full 5-stage attack timeline",
        "account_id": "sarah.chen@acme.com",
        "timeline": [
            {
                "timestamp": "2026-10-06T03:17:00",
                "event_type": "login_success",
                "source_ip": "203.0.113.77",
                "country": "RU",
                "device_id": "WIN-XK22B9",
                "detail": "Login from unfamiliar IP (Country mismatch)",
            },
            {
                "timestamp": "2026-10-06T03:18:00",
                "event_type": "failed_login",
                "failed_attempts": 8,
                "source_ip": "203.0.113.77",
                "country": "RU",
                "device_id": "WIN-XK22B9",
                "detail": "8 failed login attempts",
            },
            {
                "timestamp": "2026-10-06T03:20:00",
                "event_type": "login_success",
                "source_ip": "203.0.113.77",
                "country": "RU",
                "device_id": "WIN-XK22B9",
                "detail": "Successful login from new device",
            },
            {
                "timestamp": "2026-10-06T03:22:00",
                "event_type": "password_change",
                "detail": "Password changed",
            },
            {
                "timestamp": "2026-10-06T03:25:00",
                "event_type": "file_access",
                "files_accessed": 150,
                "detail": "150 files accessed/downloaded",
            },
        ],
    },
    {
        "name": "CRITICAL — watchlisted malicious IP + credential attack",
        "account_id": "priya.nair@acme.com",
        "timeline": [
            {
                "timestamp": "2026-10-06T02:55:00",
                "event_type": "login_success",
                "source_ip": "185.220.101.7",
                "country": "RU",
                "device_id": "LINUX-UNKNOWN",
                "detail": "Login from a known malicious IP (threat-intel hit)",
            },
            {
                "timestamp": "2026-10-06T02:56:00",
                "event_type": "failed_login",
                "failed_attempts": 8,
                "source_ip": "185.220.101.7",
                "country": "RU",
                "device_id": "LINUX-UNKNOWN",
                "detail": "8 failed login attempts",
            },
            {
                "timestamp": "2026-10-06T02:58:00",
                "event_type": "password_change",
                "detail": "Password changed",
            },
        ],
    },
]


def main() -> int:
    print(f"{CYAN}{BOLD}╔════════════════════════════════════════════════════╗")
    print("║  CYBERGUARD · SCENARIO 3 · SEED ATO EVENTS         ║")
    print(f"╚════════════════════════════════════════════════════╝{RESET}")

    env = load_env(ENV_FILE)
    gateway = env.get("GATEWAY_URL", "").strip()
    master_key = env.get("MASTER_API_KEY", "").strip()
    if not (gateway and master_key):
        sys.exit(f"{RED}{BOLD}ERROR:{RESET} backend/.env must define GATEWAY_URL and MASTER_API_KEY.")

    client = ApiClient(f"{gateway}/api/v1", master_key)
    health = client.get("/health")
    if health.status_code != 200:
        api_error(health, "backend health")
    print(f"{GREEN}✔{RESET} Backend reachable at {gateway}\n")

    results = []
    for seed in SEEDS:
        resp = client.post_json(
            "/analysis/account-takeover",
            {
                "source": "scenario_3_seed",
                "account_id": seed["account_id"],
                "baseline_profile": baseline_for(seed["account_id"]),
                "suspicious_events": seed["timeline"],
            },
        )
        if resp.status_code != 200:
            api_error(resp, f"seed '{seed['name']}'")
        data = resp.json()
        results.append((seed["name"], data))
        enforcement = data.get("enforcement") or {}
        tier = str(enforcement.get("tier", "safe")).upper()
        color = RED if tier == "CRITICAL" else (YELLOW if tier == "MEDIUM" else GREEN)
        print(
            f"{color}✔{RESET} {seed['name']}: {color}{data['risk_score']}/100 {tier}{RESET}"
            f" -> {data['action_taken']}"
        )
        print(f"{DIM}  event {data['event_id']} · alert {data['alert_id'][:8]}…{RESET}")

    print(f"\n{CYAN}{BOLD}▶ Listing org ATO events (GET /analysis/account-takeover/events){RESET}")
    listing = client.get("/analysis/account-takeover/events?limit=20")
    if listing.status_code != 200:
        api_error(listing, "list ATO events")
    for row in listing.json().get("events", []):
        color = RED if row["risk_score"] >= 75 else (YELLOW if row["risk_score"] >= 30 else GREEN)
        print(
            f"  {color}{row['risk_score']:>3}/100{RESET}  {row['action_taken']:<20} "
            f"{row['user_email']:<28} {str(row['id'])[:8]}…"
        )

    if "--json" in sys.argv:
        print(f"\n{DIM}{json.dumps([r for _, r in results], indent=2)[:4000]}{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
