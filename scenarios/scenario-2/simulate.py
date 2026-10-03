#!/usr/bin/env python3
"""CYBERGUARD — Scenario 2: Multi-tenant identity-fraud presentation sim.

Standalone demo script. It performs NO security bypasses: every request is
authenticated with the organization's real master API key (or a JWT) against
the live CyberGuard backend, and the server resolves the organization scope
from that credential — the script never supplies an organization_id.

Flow:
  1. Read GATEWAY_URL / PROJECT_SLUG / MASTER_API_KEY from backend/.env
  2. Seed a VerifiedIdentity ("John Smith", CFO) inside the authenticated org
  3. Submit the attacker payload ("John Smyth" + fake profile image) to
     POST /api/v1/analysis/identity-fraud
  4. Render the verdict as an ANSI-colored security-terminal report.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / "backend" / ".env"
ASSET = Path(__file__).resolve().parent / "assets" / "fake_ceo_profile.jpg"

# ANSI palette
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, CYAN = "\033[31m", "\033[32m", "\033[33m", "\033[36m"

ATTACK = {
    "claimed_name": "John Smyth",
    "claimed_username": "john_smith_cfo",
    "claimed_email": "john.smyth.finance@gmail.com",
    "message": (
        "I am traveling and need you to immediately purchase $5,000 in gift "
        "cards. Do not tell finance."
    ),
}

VERIFIED = {
    "name": "John Smith",
    "role_title": "CFO",
    "email": "john.smith@acme.com",
    "username": "john_smith_cfo",
}


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
    """Minimal JSON/multipart client on requests or httpx (whichever exists)."""

    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        try:
            import requests  # type: ignore

            self._lib = "requests"
            self._post_json = lambda url, payload: requests.post(
                url, json=payload, headers=self.headers, timeout=60
            )
            self._post_multipart = lambda url, data, files: requests.post(
                url, data=data, files=files, headers=self.headers, timeout=120
            )
            self._get = lambda url: requests.get(url, headers=self.headers, timeout=30)
        except ImportError:
            import httpx  # type: ignore

            self._lib = "httpx"
            self._post_json = lambda url, payload: httpx.post(
                url, json=payload, headers=self.headers, timeout=60
            )
            self._post_multipart = lambda url, data, files: httpx.post(
                url, data=data, files=files, headers=self.headers, timeout=120
            )
            self._get = lambda url: httpx.get(url, headers=self.headers, timeout=30)

    def post_json(self, path: str, payload: dict):
        return self._post_json(f"{self.base}{path}", payload)

    def post_multipart(self, path: str, fields: dict, file_path: Path):
        with open(file_path, "rb") as fh:
            files = {"media": (file_path.name, fh, "image/jpeg")}
            return self._post_multipart(f"{self.base}{path}", fields, files)

    def get(self, path: str):
        return self._get(f"{self.base}{path}")


def api_error(resp, step: str):
    try:
        detail = resp.json()
        detail = detail.get("detail") or detail.get("message") or detail
    except Exception:  # noqa: BLE001
        detail = resp.text[:300]
    sys.exit(f"{RED}{BOLD}ERROR [{step}]{RESET} HTTP {resp.status_code}: {detail}")


def http_lib_hint() -> str:
    return "requests" if ApiClient("http://x", "t")._lib == "requests" else "httpx"


def main() -> int:
    print(f"{CYAN}{BOLD}╔══════════════════════════════════════════════╗")
    print("║  CYBERGUARD · SCENARIO 2 · IDENTITY FRAUD    ║")
    print(f"╚══════════════════════════════════════════════╝{RESET}")
    print(f"{DIM}HTTP client: {http_lib_hint()} · asset: {ASSET.name}{RESET}\n")

    env = load_env(ENV_FILE)
    gateway = env.get("GATEWAY_URL", "").strip()
    project_slug = env.get("PROJECT_SLUG", "").strip()
    master_key = env.get("MASTER_API_KEY", "").strip()
    if not (gateway and project_slug and master_key):
        sys.exit(
            f"{RED}{BOLD}ERROR:{RESET} backend/.env must define "
            "GATEWAY_URL, PROJECT_SLUG and MASTER_API_KEY."
        )
    if not master_key.startswith("cg_org_"):
        print(f"{YELLOW}WARN:{RESET} MASTER_API_KEY does not look like an org key (cg_org_…)")
    if not ASSET.exists():
        sys.exit(f"{RED}{BOLD}ERROR:{RESET} missing asset {ASSET}")

    client = ApiClient(f"{gateway}/api/v1", master_key)

    health = client.get("/health")
    if health.status_code != 200:
        api_error(health, "backend health")
    print(f"{GREEN}✔{RESET} Backend reachable at {gateway}")

    # Step 1 — seed the VerifiedIdentity inside the authenticated organization.
    print(f"\n{CYAN}{BOLD}▶ STEP 1 · Seeding verified identity (org-scoped){RESET}")
    existing = client.get("/analysis/identity-fraud/verified")
    if existing.status_code != 200:
        api_error(existing, "list verified identities")
    roster = existing.json()
    if any(i.get("email") == VERIFIED["email"] for i in roster.get("identities", [])):
        print(f"{YELLOW}•{RESET} Verified identity already present (skipping seed)")
    else:
        seeded = client.post_json("/analysis/identity-fraud/verified", VERIFIED)
        if seeded.status_code not in (200, 201):
            api_error(seeded, "seed verified identity")
        org = seeded.json().get("organization_id", "?")
        print(f"{GREEN}✔{RESET} Seeded '{VERIFIED['name']}' (CFO) into organization {org}")

    # Step 2 — the attack: fraudster impersonates the verified CFO.
    print(f"\n{CYAN}{BOLD}▶ STEP 2 · Submitting attacker payload{RESET}")
    print(f"{DIM}  claimed : {ATTACK['claimed_name']} <{ATTACK['claimed_email']}>{RESET}")
    print(f"{DIM}  genuine : {VERIFIED['name']} <{VERIFIED['email']}>{RESET}")
    print(f"{DIM}  media   : {ASSET.name}{RESET}")

    resp = client.post_multipart(
        "/analysis/identity-fraud",
        {
            "claimed_name": ATTACK["claimed_name"],
            "claimed_username": ATTACK["claimed_username"],
            "claimed_email": ATTACK["claimed_email"],
            "message": ATTACK["message"],
        },
        ASSET,
    )
    if resp.status_code != 200:
        api_error(resp, "identity-fraud analysis")
    result = resp.json()

    if project_slug and result.get("project") is None:
        print(f"{YELLOW}WARN:{RESET} server resolved no project scope for this key")

    # Step 3 — presentation output.
    print(f"\n{CYAN}{BOLD}▶ STEP 3 · Verdict{RESET}\n")
    fraud = result.get("verdict") == "identity_fraud_detected"
    header = "⚠️  IDENTITY FRAUD DETECTED  ⚠️" if fraud else "⚠️  SUSPICIOUS IDENTITY ACTIVITY  ⚠️"
    bar = "=" * 40
    header_color = RED if fraud else YELLOW

    print(f"{header_color}{BOLD}{bar}")
    print(header)
    print(f"{bar}{RESET}")
    print(
        f"{DIM}org: {result.get('organization', {}).get('name', '?')}"
        f" · risk score {result.get('risk_score', 0)}/100 · alert {result.get('alert_id', '?')[:8]}…{RESET}"
    )
    print(f"{RED}{result.get('impersonation_risk', 'unknown').upper()} impersonation risk{RESET}")
    print(f"{RED}{result.get('deepfake_risk', 'unknown').upper()} deepfake risk{RESET}")

    vi = result.get("verified_identity") or {}
    if vi:
        print(f"{DIM}compared against verified identity: {vi.get('name')} <{vi.get('email')}>{RESET}")

    print(f"\n{YELLOW}{BOLD}Evidence:{RESET}")
    for item in result.get("evidence", []):
        status = item.get("status")
        if status == "danger":
            print(f"  - {RED}✗{RESET} {item.get('text')}")
        elif status == "warn":
            print(f"  - {YELLOW}!{RESET} {item.get('text')}")
        else:
            print(f"  - {GREEN}✓{RESET} {item.get('text')}")

    print(f"\n{GREEN}{BOLD}Recommended Action:{RESET}")
    for idx, action in enumerate(result.get("recommended_action", []), start=1):
        print(f"  {idx}. {action}")
    print(f"{RED}{BOLD}{bar}{RESET}")

    if "--json" in sys.argv:
        print(f"\n{DIM}{json.dumps(result, indent=2)[:4000]}{RESET}")
    return 0 if fraud else 1


if __name__ == "__main__":
    sys.exit(main())
