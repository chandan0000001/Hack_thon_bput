# Scenario 3 — Account Takeover & Abnormal Behaviour (org-scoped)

Strictly an **organization** feature: the demo authenticates with the org
`MASTER_API_KEY` from `backend/.env`, and the backend resolves the tenant
(organization + project) **server-side from the credential** — the script
never supplies an organization id.

## Run

```bash
python3 scenarios/scenario-3/simulate.py        # against GATEWAY_URL from backend/.env
python3 scenarios/scenario-3/simulate.py --json # append raw API response
```

## What it shows

1. **Normal baseline** (`assets/baseline.json`) — Sarah Chen (Finance
   Director) logs in 9–10 AM from her known IP range and known devices.
2. **Abnormal attack timeline** (`assets/attack_timeline.json`) —
   03:17 login from an unfamiliar IP (country mismatch) → 03:18 eight failed
   login attempts → 03:20 successful login from a new device → 03:22 password
   change → 03:25 150 files accessed/downloaded.
3. The timeline is submitted to `POST /api/v1/analysis/account-takeover`,
   which fuses three signals — rule engine, baseline anomaly detection and
   threat intel — into a 0–100 risk score, indicator list and recommended
   response. The Event + Alert are stamped with the authenticated
   organization/project and land in the org dashboard.
4. The verdict is rendered as the red security-terminal report.

The same flow is available in the web app under
`/org/:orgId/projects/:projectId/analysis/account-takeover`
(Org Dashboard → Analysis → Account Takeover) with a vertical timeline view.
