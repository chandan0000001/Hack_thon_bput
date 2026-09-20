# ORG-2 — Organization Dashboards + Splunk-Style Live Log Analysis

Architecture reference for the org dashboard plane (main summary + per-feature
verbose feeds) and the live log analysis stream. Built on the ORG-1
foundation (`backend/docs/org_foundation.md`); user-mode code (Phases -1
through 7) remains untouched.

## Components

| Layer | File | Purpose |
| --- | --- | --- |
| Migration | `alembic/versions/0009_org_dashboards.py` | `org_log_events` table + org RLS + realtime publication wiring |
| Model | `app/db/models.py` | `OrgLogEvent` |
| Log analysis | `app/services/org_log_analyzer.py` | shape detection (auth/network/app) + per-type detectors |
| Dashboard API | `app/api/routes_org_dashboard.py` | `GET /org/{org_id}/dashboard/summary` + `GET /org/{org_id}/dashboard/{feature}` |
| Logs API | `app/api/routes_org_logs.py` | ingest / stream / manual action |
| Tests | `scripts/test_org_dashboards.py` | Suite 18 |
| Frontend | `OrganizationDashboard.tsx`, `OrgFeatureDashboard.tsx`, `OrgLogAnalysis.tsx`, `OrgAccountTakeover.tsx`, `hooks/useOrgRealtime.ts` | dashboards + live stream |

## Data model — `org_log_events`

`id`, `organization_id` (NOT NULL, FK), `log_type` (`auth|network|app`),
`raw_data` (jsonb), `analysis_result` (jsonb: risk_score, severity,
indicators, summary, mitre_techniques), `severity`, `manual_action_taken`,
`acted_by`, `acted_at`, `created_by` (`api_key:<org_id>`), `created_at`.
Rows are created ONLY by the gateway ingest — no manual paste-boxes.

## Log type auto-detection (shape, not client-declared)

`detect_log_type(data)` samples up to 10 entries and classifies by keys:

- **auth** — `user` + `ip` (+ `status`/`location`/`device`) →
  `analyze_auth_log_heuristics` (impossible travel, brute force, MFA
  fatigue) — the same Phase-1 ATO detector used by `/analysis/account-takeover`.
- **network** — `src_ip`/`dst_ip`/`port`/`bytes` or `flows`/`api_logs` →
  `analyze_network_heuristics`.
- **app** — everything else → keyword/pattern detector (auth failures,
  invalid users, privilege escalation, injection probes, path traversal,
  malware markers, resource exhaustion) with log-level weighting.

Detection and analysis are synchronous and deterministic — **no LLM on the
ingest path** (the Splunk plane must never block on a provider). Optional
`log_type` in the payload force-overrides detection.

## Ingest → analysis → alert promotion

`POST /org/{org_id}/logs/ingest` (API-key auth, 403 on org mismatch):

1. Analyze via `analyze_log`.
2. Persist `OrgLogEvent` (insert runs under the org owner's RLS identity —
   stamped by `validate_api_key`).
3. `risk_score >= 40` (medium+) is promoted to the alert plane: an
   org-scoped `Event` + `Alert` (`module` = account_takeover / network /
   api_abuse) so dashboards and realtime see log findings. The `alert_id` is
   returned in the response.

## Dashboards

- **Summary** (`analyst+`): `total_scans` (org events), `threats_detected`
  (org alerts), `critical_alerts`, `quarantined_emails` (org
  `action_executions` with `quarantine_email`), `blocked_senders`
  (`action_type LIKE 'block%'`), `last_scan_at` (max event time).
- **Feature feeds** (`viewer+`): `feature ∈ {phishing, url, deepfake,
  impersonation}` maps to `alerts.module`; rows carry timestamp, severity,
  score, target, indicators, explanation, and the latest action taken
  (joined from `action_executions`). `limit`/`offset` pagination plus
  `severity`/`from_date`/`to_date` filters.
- **Aggregations run through the service role** with an explicit
  `organization_id` predicate: org rows are RLS owner-scoped to the creator,
  so member sessions would aggregate zero rows. Membership is enforced first
  by `require_org_role`; the service role only widens the SQL view and the
  org predicate keeps data scoped to one organization.

## Real-time

Migration 0009 adds `cyberguard.org_log_events` (row filter
`organization_id IS NOT NULL`) and `cyberguard.alerts` (unfiltered — its
nullable `organization_id` cannot be a replica-identity column; see below)
to the `supabase_realtime` publication. The frontend subscribes via
`postgres_changes` with `filter: organization_id=eq.{org_id}`
(`hooks/useOrgRealtime.ts`), with a light interval fallback for demo setups
without realtime.

**Postgres 15 constraint learned here:** a publication row filter requires
the filtered column to be part of the table's REPLICA IDENTITY — otherwise
every UPDATE/DELETE fails with *"Column used in the publication WHERE
expression is not part of the replica identity"*. `org_log_events` gets a
unique `(id, organization_id)` index + `REPLICA IDENTITY USING INDEX`;
`alerts` (nullable org column) is published unfiltered and relies on the
client filter.

**Demo tradeoff:** SELECT policies `TO authenticated` (USING true) were added
on both tables so the Supabase Realtime subscriber role can stream rows; the
app-role (`cyberguard_api`) policies remain the real isolation layer and the
REST endpoints are membership-gated. Tightening realtime-reader policies is
tracked for ORG-5 (docs/hardening).

## Manual actions on logs

`POST /org/{org_id}/logs/{log_id}/action` (analyst+; viewers get 403):

- `block_ip` / `revoke_session` (auth), `block_ip` / `isolate_host`
  (network), `escalate_incident` / `mark_safe` (app).
- Records `manual_action_taken` + `acted_by` + `acted_at` on the log row and
  writes an `audit_logs` entry (`action = org_log:<action>`, resource
  `org_log_events/<id>`, actor = the analyst).
- This records the analyst's DECISION; firing real enforcement targets
  (firewall blocklists, session stores) is wired in ORG-3+ when connector
  integrations exist. `mark_safe` is rejected if the row is already resolved.

## RLS on `org_log_events`

Via `cyberguard.org_member_role()` (ORG-1 function): SELECT for members,
INSERT for admins (gateway ingest runs under the owner identity), UPDATE for
analysts+, DELETE for admins. Suite 18 asserts cross-org API (403) and
raw-RLS (0 rows) isolation. Since migration 0016 (ORG-FIX-1) this isolation
is genuinely DB-enforced for the app role too — the baseline's permissive
`org_log_events_app_all USING (true)` policy (which OR-combined above every
gated policy) is dropped; gateway key validation goes through the narrow
SECURITY DEFINER `cyberguard.validate_org_api_key(p_hash)` instead.

## Frontend routes

- `/org/:orgId/dashboard` — summary cards (live badge; realtime + 15 s
  fallback) + module grid.
- `/org/:orgId/dashboard/:feature` — verbose table (severity badge, score,
  target, action taken) + filters + detail drawer (indicators, explanation).
- `/org/:orgId/logs` — Splunk-style stream (newest first, type badge,
  severity, summary) with per-row manual action buttons (hover-revealed,
  hidden once resolved) and a detail drawer (analysis JSON + raw log).
- `/org/:orgId/account-takeover` — Coming Soon placeholder (disabled state,
  per the Excalidraw spec).
