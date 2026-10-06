#!/usr/bin/env python3
"""CYBERGUARD — Scenario 3: Account takeover & abnormal behaviour sim.

Standalone demo script. It performs NO security bypasses: the request is
authenticated with the organization's real MASTER_API_KEY from backend/.env
against the live CyberGuard backend, and the server resolves the
organization/project scope from that credential — the script never supplies
an organization_id (the API rejects client-supplied tenant scopes by design).

Flow:
  1. Read GATEWAY_URL / PROJECT_SLUG / MASTER_API_KEY from backend/.env
  2. Load the "Normal Baseline" (assets/baseline.json): Sarah Chen logs in
     9-10 AM from her known IP and known MacBook.
  3. Load the "Abnormal Attack Timeline" (assets/attack_timeline.json):
     03:17 unfamiliar-IP login -> 03:18 8 failed attempts -> 03:20 success
     from a new device -> 03:22 password change -> 03:25 150 files accessed.
  4. POST /api/v1/analysis/account-takeover (org-scoped fusion engine).
  5. Render the verdict as an ANSI-colored security-terminal report.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / "backend" / ".env"
ASSETS = Path(__file__).resolve().parent / "assets"
BASELINE_FILE = ASSETS / "baseline.json"
TIMELINE_FILE = ASSETS / "attack_timeline.json"

# ANSI palette
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN = "\033[31m", "\033[32m", "\033[33m", "\033[36m"

LEVEL_COLORS = {"critical": RED, "high": RED, "medium": YELLOW, "low": GREEN}


def load_env(path: Path) -> dict[str, str]:
    if not path.exists():
        sys.exit(f"{RED}{BOLD}ERROR:{RESET} {path} not found.")
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


class ApiClient:
    """Minimal JSON client on requests or httpx (whichever exists)."""

    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        try:
            import requests  # type: ignore

            self._post_json = lambda url, payload: requests.post(  # noqa: E731
                url, json=payload, headers=self.headers, timeout=60
            )
            self._patch_json = lambda url, payload: requests.patch(  # noqa: E731
                url, json=payload, headers=self.headers, timeout=60
            )
            self._get = lambda url: requests.get(url, headers=self.headers, timeout=30)  # noqa: E731
        except ImportError:
            import httpx  # type: ignore

            self._post_json = lambda url, payload: httpx.post(  # noqa: E731
                url, json=payload, headers=self.headers, timeout=60
            )
            self._patch_json = lambda url, payload: httpx.patch(  # noqa: E731
                url, json=payload, headers=self.headers, timeout=60
            )
            self._get = lambda url: httpx.get(url, headers=self.headers, timeout=30)  # noqa: E731

    def post_json(self, path: str, payload: dict):
        return self._post_json(f"{self.base}{path}", payload)

    def patch_json(self, path: str, payload: dict):
        return self._patch_json(f"{self.base}{path}", payload)

    def get(self, path: str):
        return self._get(f"{self.base}{path}")


def api_error(resp, step: str):
    try:
        detail = resp.json()
        detail = detail.get("detail") or detail.get("message") or detail
    except Exception:  # noqa: BLE001
        detail = resp.text[:300]
    sys.exit(f"{RED}{BOLD}ERROR [{step}]{RESET} HTTP {resp.status_code}: {detail}")


def main() -> int:
    print(f"{CYAN}{BOLD}╔════════════════════════════════════════════════════╗")
    print("║  CYBERGUARD · SCENARIO 3 · ACCOUNT TAKEOVER (ATO)  ║")
    print(f"╚════════════════════════════════════════════════════╝{RESET}")

    env = load_env(ENV_FILE)
    gateway = env.get("GATEWAY_URL", "").strip()
    project_slug = env.get("PROJECT_SLUG", "").strip()
    master_key = env.get("MASTER_API_KEY", "").strip()
    if not (gateway and master_key):
        sys.exit(
            f"{RED}{BOLD}ERROR:{RESET} backend/.env must define "
            "GATEWAY_URL and MASTER_API_KEY."
        )
    if not master_key.startswith("cg_org_"):
        print(f"{YELLOW}WARN:{RESET} MASTER_API_KEY does not look like an org key (cg_org_…)")
    print(f"{DIM}gateway: {gateway} · project: {project_slug or '?'} · auth: org MASTER_API_KEY{RESET}\n")

    if not BASELINE_FILE.exists() or not TIMELINE_FILE.exists():
        sys.exit(f"{RED}{BOLD}ERROR:{RESET} missing scenario assets under {ASSETS}")
    baseline_doc = json.loads(BASELINE_FILE.read_text())
    timeline = json.loads(TIMELINE_FILE.read_text())

    client = ApiClient(f"{gateway}/api/v1", master_key)

    health = client.get("/health")
    if health.status_code != 200:
        api_error(health, "backend health")
    print(f"{GREEN}✔{RESET} Backend reachable at {gateway}")

    # Step 1 — the normal baseline: user logs in 9-10 AM, known IP, known device.
    print(f"\n{CYAN}{BOLD}▶ STEP 1 · Normal Baseline{RESET}")
    baseline = baseline_doc["baseline_profile"]
    account = baseline_doc.get("account_id") or baseline.get("user", "user")
    print(f"{DIM}  account : {account}{RESET}")
    print(f"{DIM}  hours   : {baseline.get('typical_login_start')}–{baseline.get('typical_login_end')} local{RESET}")
    print(f"{DIM}  country : {baseline.get('home_country')}{RESET}")
    print(f"{DIM}  known IPs     : {', '.join(baseline.get('known_ips', []))}{RESET}")
    print(f"{DIM}  known devices : {', '.join(baseline.get('known_devices', []))}{RESET}")

    # Step 2 — the abnormal attack timeline.
    print(f"\n{CYAN}{BOLD}▶ STEP 2 · Abnormal Attack Timeline{RESET}")
    for event in timeline:
        clock = str(event.get("timestamp", ""))[11:16]
        print(f"{RED}  ✗{RESET} {clock}  {event.get('detail', event.get('event_type', '?'))}")

    # Step 3 — send to the org-scoped API (org resolved from the key server-side).
    print(f"\n{CYAN}{BOLD}▶ STEP 3 · POST /api/v1/analysis/account-takeover{RESET}")
    resp = client.post_json(
        "/analysis/account-takeover",
        {
            "source": "scenario_3_sim",
            "account_id": account,
            "baseline_profile": baseline,
            "suspicious_events": timeline,
        },
    )
    if resp.status_code != 200:
        api_error(resp, "account-takeover analysis")
    result = resp.json()

    if result.get("project") is None:
        print(f"{YELLOW}WARN:{RESET} server resolved no project scope for this key")

    # Step 4 — presentation output.
    print(f"\n{CYAN}{BOLD}▶ STEP 4 · Verdict{RESET}\n")
    takeover = result.get("verdict") == "account_takeover_detected"
    level = str(result.get("risk_level", "unknown")).upper()
    score = result.get("risk_score", 0)
    bar = "=" * 40
    header = "⚠️  POSSIBLE ACCOUNT TAKEOVER  ⚠️" if takeover else "NO ACCOUNT TAKEOVER DETECTED"
    header_color = RED if takeover else GREEN

    print(f"{header_color}{BOLD}{bar}")
    print(header)
    print(f"{bar}{RESET}")
    level_color = LEVEL_COLORS.get(str(result.get("risk_level", "")), YELLOW)
    print(f"{level_color}Risk Level: {level} (Score: {score}/100){RESET}")
    org = result.get("organization", {})
    print(
        f"{DIM}org: {org.get('name', '?')} · alert {str(result.get('alert_id', '?'))[:8]}…{RESET}"
    )

    print(f"\n{YELLOW}Detected Indicators:{RESET}")
    for indicator in result.get("indicators", []):
        print(f"  - {RED}✗{RESET} {indicator.get('description')}")

    print(f"\n{GREEN}Recommended Response:{RESET}")
    for idx, action in enumerate(result.get("recommended_actions", []), start=1):
        print(f"  {idx}. {action}")
    print(f"{RED}{BOLD}{bar}{RESET}")

    if "--json" in sys.argv:
        print(f"\n{DIM}{json.dumps(result, indent=2)[:4000]}{RESET}")
    return 0 if takeover else 1


if __name__ == "__main__":
    sys.exit(main())
