# Scenario 2 — Multi-Tenant Identity Fraud (Presentation Sim)

This scenario simulates a **secure, organization-scoped identity-fraud attack**:
a fraudster impersonates a verified CFO ("John Smith", `john.smith@acme.com`)
with a look-alike name ("John Smyth"), a mimic username, a personal Gmail
address, a pressure/gift-card message, and a manipulated profile image.

**No security bypasses are used.** The script authenticates against the live
CyberGuard backend with the organization's real master API key. The backend
resolves the organization/project scope **server-side from the credential**
(the `cyberguard.org_api_keys` row via the `validate_org_api_key` security
definer) — the script never sends an `organization_id`, so the demo cannot
read, seed, or analyze against another tenant's data.

## What it does

1. **Seed verified identity** — `POST /api/v1/analysis/identity-fraud/verified`
   creates a `VerifiedIdentity` row scoped to the authenticated organization.
2. **The attack** — `POST /api/v1/analysis/identity-fraud` (multipart) submits
   the attacker payload (claimed name / username / email, gift-card message,
   and `assets/fake_ceo_profile.jpg`) with the same authenticated headers.
3. **Presentation output** — the JSON verdict is rendered as a colored
   security-terminal report (impersonation risk, deepfake risk, evidence,
   recommended actions).

Backend side: `backend/app/api/routes_analysis.py` (endpoints
`/analysis/identity-fraud*`), model `VerifiedIdentity`, migration
`0104_verified_identities` (org-scoped RLS). Every analysis persists an Event
and Alert under the authenticated tenant.

## Prerequisites

1. Dev database running (`docker compose -f docker-compose.dev.yml up -d`) and
   migrated: `cd backend && uv run alembic upgrade head`.
2. Backend running: `cd backend && uv run uvicorn app.main:app --port 8000`.
3. `backend/.env` contains a valid demo tenant:

   ```env
   GATEWAY_URL=http://localhost:8000
   PROJECT_SLUG=executive-fraud-watch
   MASTER_API_KEY=cg_org_...
   ```

   `MASTER_API_KEY` must be an active **master** key of the project in
   `PROJECT_SLUG` (create one in the org workspace under Project Settings →
   API Keys, or reuse the seeded demo tenant).

## Run

```bash
python scenarios/scenario-2/simulate.py          # terminal report
python scenarios/scenario-2/simulate.py --json   # also dump the raw API JSON
```

Requires `requests` or `httpx` on the interpreter (the backend venv has both:
`uv run python scenarios/scenario-2/simulate.py`).

## Files

- `simulate.py` — the presentation script
- `assets/fake_ceo_profile.jpg` — dummy attacker profile image (valid JPEG)
