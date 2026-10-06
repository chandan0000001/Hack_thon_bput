#!/usr/bin/env python3
"""CYBERGUARD — Scenario 3: rich multi-level demo + cinematic terminal UI.

Seeds three account-takeover cases across the risk spectrum through the REAL
API (org MASTER_API_KEY from backend/.env — the server resolves the tenant;
no bypasses), lets the 3-tier engine execute automatically, performs the
analyst's manual override on the critical case, and prints a SOC-style
terminal dashboard:

  View 1  the Account Takeover event feed (list view)
  View 2  the drill-down of the critical event: attack timeline + the hybrid
          action center showing Automatic vs Manual executions.

Cases (weights are the detector's calibrated scoring):
  Sarah Chen (Exec)    08:41 login, secondary tablet, known US IP  -> SAFE
  David Kim (Dev)      11:45 login from Germany, 2 failed, 65 files -> MEDIUM
  Lisa Wong (Finance)  03:17 attack: 10 failed, new device, RU IP,
                       password change, 150 files                  -> CRITICAL
  ...plus the analyst manual override: force password reset on Lisa.

Usage:  uv run --project backend python scenarios/scenario-3/demo.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from simulate import ENV_FILE, ApiClient, api_error, load_env  # noqa: E402

# ANSI palette — CyberGuard terminal rules: RED critical, YELLOW medium,
# GREEN safe/success, CYAN headers, BLUE automatic, MAGENTA manual.
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN, BLUE, MAGENTA = (
    "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[34m", "\033[35m",
)

WIDTH = 76

BASELINE = {
    "role": "baseline template",
    "typical_login_start": "09:00",
    "typical_login_end": "10:00",
    "home_country": "US",
    "known_ips": ["98.42.117.6", "10.0.4.15"],
    "known_devices": ["MAC-BOOK-A7F3", "IPHONE-12-SARAH"],
}


def baseline_for(account_id: str, devices: list[str]) -> dict:
    b = dict(BASELINE)
    b["user"] = account_id
    b["known_devices"] = devices
    return b


SARAH = "sarah.chen@acme.com"
DAVID = "david.kim@acme.com"
LISA = "lisa.wong@acme.com"

# --- the three seeded cases -------------------------------------------------
CASES = [
    {
        "tag": "EVT-001",
        "account_id": SARAH,
        "role": "Executive",
        "baseline": baseline_for(SARAH, ["MAC-BOOK-A7F3"]),
        "timeline": [
            {
                "timestamp": "2026-10-06T08:41:00",
                "event_type": "login_success",
                "source_ip": "98.42.117.6",
                "country": "US",
                "device_id": "IPHONE-12-SARAH",
                "detail": "Early login from secondary tablet on the known office IP",
            },
        ],
    },
    {
        "tag": "EVT-002",
        "account_id": DAVID,
        "role": "Developer",
        "baseline": baseline_for(DAVID, ["MAC-DEV-DAVID"]),
        "timeline": [
            {
                "timestamp": "2026-10-06T11:45:00",
                "event_type": "failed_login",
                "failed_attempts": 2,
                "source_ip": "88.198.22.10",
                "country": "DE",
                "device_id": "DESKTOP-DAVID-NEW",
                "detail": "Two failed attempts, then a login from Germany",
            },
            {
                "timestamp": "2026-10-06T11:45:30",
                "event_type": "login_success",
                "source_ip": "88.198.22.10",
                "country": "DE",
                "device_id": "DESKTOP-DAVID-NEW",
                "detail": "Successful login from a new country and device",
            },
            {
                "timestamp": "2026-10-06T11:52:00",
                "event_type": "file_access",
                "files_accessed": 65,
                "detail": "Bulk access to 65 repository files",
            },
        ],
    },
    {
        "tag": "EVT-003",
        "account_id": LISA,
        "role": "Finance",
        "baseline": baseline_for(LISA, ["MAC-BOOK-LW"]),
        "timeline": [
            {
                "timestamp": "2026-10-06T03:17:00",
                "event_type": "login_success",
                "source_ip": "203.0.113.77",
                "country": "RU",
                "device_id": "WIN-XK22B9",
                "detail": "Login from unfamiliar IP (Country mismatch: RU)",
            },
            {
                "timestamp": "2026-10-06T03:18:00",
                "event_type": "failed_login",
                "failed_attempts": 10,
                "source_ip": "203.0.113.77",
                "country": "RU",
                "device_id": "WIN-XK22B9",
                "detail": "10 failed login attempts",
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
]


def fmt_clock(iso: str | None) -> str:
    if not iso or "T" not in iso:
        return "--:-- --"
    hh, mm = iso.split("T")[1].split(":")[:2]
    hour = int(hh)
    return f"{hour % 12 or 12:02d}:{mm} {'AM' if hour < 12 else 'PM'}"


def tier_color(tier: str) -> str:
    return {"critical": RED, "medium": YELLOW}.get(tier, GREEN)


def status_text(row: dict) -> str:
    action = row.get("action_taken")
    if action == "ACCOUNT_RESTRICTED":
        return "RESTRICTED (Auto) + Notified"
    if action == "USER_NOTIFIED":
        return "NOTIFIED (Auto)"
    return "ALLOWED (Safe)"


def box(title: str, color: str = CYAN) -> None:
    print(f"{color}╔{'═' * WIDTH}╗")
    print(f"║  {title.ljust(WIDTH - 4)}║")
    print(f"╚{'═' * WIDTH}╝{RESET}")


def solid_box(title: str, color: str = RED) -> None:
    print(f"{color}{BOLD}{'═' * (WIDTH + 2)}")
    print(f"  {title}")
    print(f"{'═' * (WIDTH + 2)}{RESET}")


def main() -> int:
    print()
    box("CYBERGUARD SOC · SCENARIO 3 · ACCOUNT TAKEOVER — LIVE DEMO")
    print(f"{DIM}  seeding multi-level events through the org MASTER_API_KEY "
          f"(tenant resolved server-side){RESET}\n")

    env = load_env(ENV_FILE)
    gateway = env.get("GATEWAY_URL", "").strip()
    master_key = env.get("MASTER_API_KEY", "").strip()
    if not (gateway and master_key):
        sys.exit(f"{RED}{BOLD}ERROR:{RESET} backend/.env must define GATEWAY_URL and MASTER_API_KEY.")
    client = ApiClient(f"{gateway}/api/v1", master_key)
    if client.get("/health").status_code != 200:
        sys.exit(f"{RED}{BOLD}ERROR:{RESET} backend unreachable at {gateway}")
    print(f"{GREEN}✔{RESET} Backend live at {gateway}\n")

    # ------------------------------------------------------------------
    # STEP 1 — seed the three cases through the API (auto-execution fires
    # inside the backend according to the 3-tier enforcement).
    # ------------------------------------------------------------------
    print(f"{CYAN}{BOLD}▶ STEP 1 · Seeding multi-level events (API){RESET}")
    seeded: dict[str, dict] = {}
    for case in CASES:
        resp = client.post_json(
            "/analysis/account-takeover",
            {
                "source": "scenario_3_rich_demo",
                "account_id": case["account_id"],
                "baseline_profile": case["baseline"],
                "suspicious_events": case["timeline"],
            },
        )
        if resp.status_code != 200:
            api_error(resp, f"seed {case['tag']}")
        data = resp.json()
        seeded[case["tag"]] = {"case": case, "data": data}
        tier = data.get("enforcement", {}).get("tier", "safe").upper()
        color = tier_color(tier.lower())
        print(
            f"  {color}{case['tag']}{RESET} {case['account_id']:<22} -> "
            f"{color}{data['risk_score']}/100 {tier}{RESET} "
            f"· action: {data.get('action_taken')}"
        )

    # ------------------------------------------------------------------
    # STEP 2 — the analyst's manual override on the critical event.
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}▶ STEP 2 · Analyst override on the critical event{RESET}")
    crit = seeded["EVT-003"]["data"]
    patch = client.patch_json(
        f"/analysis/account-takeover/events/{crit['event_id']}/action",
        {"action": "force_password_reset"},
    )
    if patch.status_code != 200:
        api_error(patch, "manual override")
    pdata = patch.json()
    print(
        f"  {MAGENTA}✔{RESET} Analyst reviewed EVT-003 and manually forced a "
        f"password reset -> {pdata.get('status')} "
        f"(action_status: {pdata.get('action_status')})"
    )

    # ------------------------------------------------------------------
    # STEP 3 — VIEW 1: the event feed (list view, from the live list API).
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}▶ STEP 3 · Opening the event feed{RESET}")
    time.sleep(1)  # simulate the analyst clicking into the feed
    listing = client.get("/analysis/account-takeover/events?limit=100")
    if listing.status_code != 200:
        api_error(listing, "list ATO events")
    by_id = {row["id"]: row for row in listing.json().get("events", [])}

    print()
    box("CYBERGUARD SOC · ACCOUNT TAKEOVER EVENT FEED")
    print(f"{DIM}  {'ID'.ljust(10)}| {'Time'.ljust(10)}| {'User'.ljust(24)}| "
          f"{'Risk'.ljust(8)}| Status{RESET}")
    for case in CASES:
        tag = case["tag"]
        row = by_id.get(seeded[tag]["data"]["event_id"])
        if row is None:
            print(f"  {RED}✖ {tag} missing from feed!{RESET}")
            continue
        clock = fmt_clock(case["timeline"][0]["timestamp"])
        short_user = case["account_id"].split("@")[0] + "@acme"
        tier = row.get("tier", "safe")
        color = tier_color(tier)
        mark = {"critical": "✖", "medium": "⚠"}.get(tier, "✔")
        risk = f"{row['risk_score']}/100"
        print(
            f"  {color}{mark} {tag.ljust(9)}| {clock.ljust(10)}| "
            f"{short_user.ljust(24)}| {risk.ljust(8)}| "
            f"{status_text(row)}{RESET}"
        )
    print(f"{DIM}  {'—' * 74}{RESET}")
    print(f"{DIM}  org scope resolved server-side · GREEN safe · YELLOW medium · RED critical{RESET}")

    # ------------------------------------------------------------------
    # STEP 4 — VIEW 2: drill-down of the critical event.
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}▶ STEP 4 · Analyst selects EVT-003 …{RESET}")
    time.sleep(1)  # simulate the click
    detail_resp = client.get(
        f"/analysis/account-takeover/events/{crit['event_id']}"
    )
    if detail_resp.status_code != 200:
        api_error(detail_resp, "drill down")
    detail = detail_resp.json()

    print()
    solid_box(f"DRILL DOWN: EVT-003 (CRITICAL ACCOUNT TAKEOVER — {LISA})")
    print(
        f"\n  risk {RED}{BOLD}{detail['risk_score']}/100 · {detail['risk_level'].upper()}{RESET}"
        f"{DIM} · enforced: {detail.get('action_taken')}{RESET}"
    )

    print(f"\n  {YELLOW}⏱ ATTACK TIMELINE:{RESET}")
    for event in detail.get("suspicious_events", []):
        clock = fmt_clock(event.get("timestamp"))
        text = event.get("detail") or event.get("event_type", "event")
        mark = "✖" if event.get("flagged") else " "
        print(f"    {RED}{mark}{RESET} {RED}{clock}{RESET} - {text}")

    print(f"\n  {YELLOW}⚡ HYBRID ACTION CENTER:{RESET}")
    ledger = detail.get("action_ledger", {})
    for action, label in (
        ("restrict_account", "Restrict Account"),
        ("notify_user", "Notify User"),
        ("force_password_reset", "Force Password Reset"),
    ):
        entry = ledger.get(action) or {}
        status = entry.get("status")
        if status == "done_manual":
            mark, how = f"{GREEN}✔", f"DONE (Manual - Analyst)"
        elif status == "done_auto":
            mark, how = f"{BLUE}✔", f"DONE (Automatic)"
        else:
            mark, how = f"{DIM}○", "PENDING"
        dots = "…" * max(2, 26 - len(label))
        print(f"    {mark} {label} {dots} {GREEN if status else DIM}{how}{RESET}")

    print(f"\n{DIM}  analysis: {detail.get('explanation', '')[:110]}…{RESET}")
    box("DEMO COMPLETE · 3 TIERS EXECUTED · HYBRID AUTO + MANUAL AUDIT TRAIL", GREEN)
    return 0


if __name__ == "__main__":
    sys.exit(main())
