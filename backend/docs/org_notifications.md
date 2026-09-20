# ORG-4 — Org Email Notification Groups

"Send email to registered mails": multiple registered addresses grouped by
role, with per-event-type routing. Org-level — entirely separate from the
per-user `notification_email` of Phase 7 (whose code paths are untouched).
Built on ORG-1..3.

## Components

| Layer | File | Purpose |
| --- | --- | --- |
| Migration | `alembic/versions/0011_org_email_groups.py` | 3 tables + RLS (viewer blocked) |
| Models | `app/db/models.py` | `OrgNotificationEmail`, `OrgNotificationSetting`, `OrgNotificationLog` |
| Service | `app/services/org_notification_service.py` | `send_event`, role-group filtering, HTML templates, default event taxonomy |
| Routes | `app/api/routes_org_notifications.py` | emails CRUD, settings list/update, log history |
| Triggers | `routes_org_mail.py`, `routes_org_logs.py`, `routes_orgs.py` | event sources |
| Tests | `scripts/test_org_notifications.py` | Suite 20 |

## Role-group model

Each registered address belongs to a role group (`admin | analyst | viewer`);
each event type declares the **minimum** role group that receives it:

- `min_role = admin` → admins only
- `min_role = analyst` → analysts + admins
- `min_role = viewer` → everyone

Defaults seeded on first read: `server_down`→analyst, `mail_server_down`→
analyst, `critical_log`→analyst, `impersonation`→admin (impersonation is
brand/reputation-sensitive, so admins only by default).

## Event taxonomy and triggers

| Event type | Trigger source | Where |
| --- | --- | --- |
| `mail_server_down` | connect with invalid/incomplete credentials fails | `routes_org_mail._apply_connect` |
| `server_down` | fetch fails on a connected mail server | `routes_org_mail.fetch_recent_emails` |
| `critical_log` | gateway log ingest scores medium+ | `routes_org_logs.ingest_org_log` (promotion branch) |
| `impersonation` | gateway `scan_email` finds lookalike-domain / display-name-spoof / reply-to-mismatch indicators | `routes_orgs._gateway_scan_email` |

Delivery reuses the Phase 7 backend (`notification_service._deliver`):
DB-logged by default (demo-safe), best-effort SMTP when
`NOTIFICATION_SMTP_HOST` is configured, per-recipient error isolation.
Every send persists an `org_notification_logs` row with per-recipient
outcomes (`{email, role, status, backend, error_detail}`) and overall status
`sent | failed | skipped`. A disabled event type produces no sends and no
log row (send_event returns silently); a disabled address is simply excluded
from recipient selection.

## Endpoints (under `/api/v1/org/{org_id}/notifications`)

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/emails` | analyst+ | Registered addresses (role, enabled) |
| POST | `/emails` | admin | Register address (format-validated, org-unique) |
| PUT | `/emails/{id}` | admin | Change role group / enable-disable |
| DELETE | `/emails/{id}` | admin | Remove address |
| GET | `/settings` | analyst+ | Event types with min_role + enabled (seeds defaults) |
| PUT | `/settings/{event_type}` | admin | Update min_role / enabled |
| GET | `/logs` | analyst+ | Delivery history; filters `event_type`, `status`, `from_date`, `to_date`; paginated |

## RLS (migration 0011)

All three tables: SELECT for admins+analysts only (**viewer blocked** at RLS
and API); writes admin-only. Predicates use `cyberguard.org_member_role()`.
Suite 20 asserts viewer 403s, analyst write 403s, and raw-RLS cross-org
isolation (0 rows for an outsider under the app role). Migration 0016
(ORG-FIX-1) dropped the permissive `*_app_all USING (true)` policies on all
three tables, so this isolation holds at the DB layer for the app role, not
only at the API layer (previously the permissive policies OR-combined above
the gated ones).

## Frontend

- `/org/:orgId/notifications` — three sections: Registered Emails (role
  dropdown + enabled toggle + delete), Event Type Routing (min-role dropdown
  with plain-language explanation + toggle), Recent Deliveries (collapsible
  rows with per-recipient outcomes). "Add Email" modal with role selector.
- `/org/:orgId/notifications/logs` — dedicated history page with event
  type / status / date-range filters and expandable per-recipient details +
  event metadata.
- "Email Groups" card on the Organization Dashboard grid.
