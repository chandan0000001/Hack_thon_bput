# CYBERGUARD — Frontend Architecture

**Stack:** React 18.3 · TypeScript 5.2 · Vite · react-router-dom 7.18 · Zustand 4.4 · Recharts 2.9 · Tailwind CSS 3.3 · lucide-react · Supabase JS 2.45

The frontend is a hand-built (no component library) dark SOC console: a monochrome black/white/red design system, realtime-driven quarantine queue, six forensic analysis pages, a dual personal/organization workspace model, and an admin operations plane (DLQ, policies, approvals).

**Related documents:** [API_DOCUMENTATION.md](API_DOCUMENTATION.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) · [MONITORING_OBSERVABILITY.md](MONITORING_OBSERVABILITY.md)

## Table of Contents

1. [Application Bootstrap & Routing](#1-application-bootstrap--routing)
2. [Component Hierarchy](#2-component-hierarchy)
3. [State Management (Zustand)](#3-state-management-zustand)
4. [API Integration Patterns](#4-api-integration-patterns)
5. [Real-Time Subscriptions](#5-real-time-subscriptions)
6. [UI/UX Workflows](#6-uiux-workflows)
7. [Design System](#7-design-system)
8. [Testing & Verification](#8-testing--verification)
9. [FAQ](#9-faq)

---

## 1. Application Bootstrap & Routing

`App.tsx` mounts `BrowserRouter`, renders public routes, then wraps every authenticated route in `ProtectedRoute → MainLayout`:

```mermaid
flowchart TB
    MAIN["main.tsx"] --> APP["App.tsx · BrowserRouter"]
    APP --> PUB["Public: /login · /reset-password · / · * → /"]
    APP --> GUARD["ProtectedRoute (hydrated session?)"]
    GUARD --> LAYOUT["MainLayout (Sidebar · Topbar · SocAssistant)"]
    LAYOUT --> ROUTES["40 authenticated routes"]

    ROUTES --> G1["WorkspaceGuard — org-scoped route without<br/>an active non-personal org → ComingSoon"]
    ROUTES --> G2["RoleGuard minimumRole — e.g. /dlq, /policies,<br/>/admin/users require admin"]
    ROUTES --> G3["OrgFeature — renders ComingSoon when<br/>server reports orgEnabled=false"]
```

### Route Map

| Scope | Routes |
|---|---|
| Analysis (personal + org) | `/dashboard` · `/phishing` · `/url-analysis` · `/impersonation` · `/deepfake` · `/log-analysis` |
| Email security | `/email-connectors` · `/quarantine` · `/blocked-senders` · `/notification-log` · `/security-history` |
| SOC plane (org) | `/alerts` (+`/:id`) · `/incidents` (+`/:id`) · `/response-actions` · `/approvals` · `/blocklist` · `/action-log` · `/audit-logs` · `/reports` · `/account-takeover` · `/network-threats` |
| Administration (org + admin) | `/policies` · `/admin/users` · `/dlq` |
| Organization plane | `/organization` · `/org/create` · `/org/:orgId/settings` · `/org/:orgId/dashboard(/:feature)` · `/org/:orgId/logs` · `/org/:orgId/account-takeover` · `/org/:orgId/mail-servers(/:serverId/logs|settings)` · `/org/:orgId/notifications(/logs)` |
| Misc | `/settings` · `/docs` |

**Why guards render placeholders instead of redirecting:** `WorkspaceGuard` renders a `ComingSoon` panel rather than bouncing the URL — the backend's 501/403 responses remain the second line of defense, and the address bar stays honest.

### Single Nav Source

`nav.ts` is the only navigation list: each `NavItem` carries `to, label, icon, scope ('user'|'org'|'both'), section ('analyze'|'mailbox'|'history'|'org'|'system'), adminOnly?`. `Sidebar`, `WorkspaceGuard`, and `isOrgScopeRoute()` all consume it, so moving a feature between scopes is a one-line change (ADR: workspace-scoped navigation).

---

## 2. Component Hierarchy

```mermaid
flowchart TB
    APP["App"] --> ML["layout/MainLayout"]
    ML --> SB["layout/Sidebar<br/>(nav.ts sections)"]
    ML --> TB["layout/Topbar<br/>(workspace switcher · LIVE pill · toasts)"]
    ML --> SA["layout/SocAssistant (ephemeral chat)"]
    ML --> PG["pages/*"]

    PG --> CC["common/ components"]
    subgraph CC
        RG["RiskGauge · SeverityBadge · StatusPill"]
        DT["DataTable · StatCard · ChartCard · EmptyState"]
        FX["ExplanationPanel · IndicatorList · MitreTags ·<br/>RecommendedActionsPanel · VerboseResultPanel"]
        IO["FileUpload · LoadingSkeleton · Toast · PageHeader"]
    end

    PG --> CH["Recharts visualizations<br/>(AreaChart · BarChart · PieChart)"]
```

---

## 3. State Management (Zustand)

Three small stores — no global data cache, no Redux-style normalization:

```mermaid
flowchart LR
    subgraph Stores["Zustand Stores"]
        AUTH["authStore<br/>user · accessToken · role (viewer/analyst/admin)<br/>orgEnabled · organizations · activeOrganizationId<br/>actions: login · signUp · hydrate · fetchUserContext ·<br/>switchOrganization · logout · can('analyze'|'mutate'|'admin')"]
        UI["uiStore<br/>sidebarCollapsed · liveSimulation · assistantOpen · toasts"]
        RT["useRealtimeEmailStore<br/>liveCount · lastEvent · seenIds (dedup)"]
    end
    LS[("localStorage<br/>cyberguard_active_org")] --> AUTH
    SUPA[("Supabase JS session storage<br/>(access + refresh tokens)")] --> AUTH
```

**Persistence model:** the only custom persisted value is `activeOrganizationId` (localStorage `cyberguard_active_org`). The auth session itself lives in Supabase's own localStorage; `hydrate()` restores it on boot and re-fetches `/auth/me`. There is deliberately no `zustand/persist` middleware keeping tokens in app-managed stores.

**Login flow:** `login()` posts `{identifier, password}` to `/auth/signin`, then installs the returned session with `supabase.auth.setSession` — keeping Supabase-managed refresh and the realtime websocket auth in sync with the backend session.

---

## 4. API Integration Patterns

```mermaid
flowchart TB
    PAGES["pages/*"] --> API["services/api.ts<br/>THE only module pages import"]
    PAGES --> ORG["services/orgApi.ts<br/>(/orgs + /org/{id} plane)"]
    API & ORG --> HTTP["services/http.ts · apiFetch()"]
    HTTP --> H1["Headers: Content-Type json (unless FormData)<br/>Authorization: Bearer <authStore token><br/>X-Organization-Id: <active org>"]
    HTTP --> H2["On 401: supabase.auth.refreshSession()<br/>→ retry once → else logout + 'Session expired'"]
    HTTP --> H3["Error parsing: FastAPI detail string ·<br/>validation {msg} arrays · message field · 204 → null"]
    HTTP --> REST["FastAPI /api/v1"]
    HTTP -.->|"VITE_USE_MOCK=true"| MOCK["In-browser mock adapters<br/>(demo mode, amber DEMO badge)"]
```

- **`mappers.ts`** normalizes backend payloads into the strict domain types in `types/index.ts` (626 lines: `Alert`, `AnalysisResult`, `QuarantinedItem`, `DlqJob`, …).
- **`severity.ts`** derives the UI band from a 0–100 score: safe ≤20 · low ≤40 · medium ≤60 · high ≤80 · critical >80.
- **Why a facade?** One import boundary for every endpoint means auth headers, refresh-on-401, and error shaping are applied exactly once.

---

## 5. Real-Time Subscriptions

All realtime runs through **Supabase Realtime** (the backend holds no websockets):

```mermaid
sequenceDiagram
    autonumber
    participant EW as email-worker
    participant SR as Supabase Realtime
    participant H as useRealtimeEmails
    participant ST as useRealtimeEmailStore
    participant Q as QuarantineQueue page

    EW->>SR: broadcast email_analyzed → channel user:{userId}
    SR->>H: websocket payload
    H->>ST: dedupe via seenIds · liveCount++
    H->>Q: prepend item + highlight animation
    Q->>Q: shouldAutoScrollToTop? (critical OR risk≥0.8, scrollY<120)
    Note over H: Connection states:<br/>SUBSCRIBED → LIVE pill<br/>CHANNEL_ERROR / TIMED_OUT (5 s) / CLOSED → POLLING
    H->>H: 60 s polling via quarantine list endpoint<br/>silent — no error toast, resumes on reconnect
```

| Hook | Channel | Mechanism | Filter |
|---|---|---|---|
| `useRealtimeEmails` | `user:{userId}` | broadcast `email_analyzed` | — (5 s timeout → 60 s polling fallback) |
| `useRealtimeAlerts` | `cyberguard-alerts` | `postgres_changes INSERT` on `public.alerts` | toast + refresh |
| `useOrgRealtime` | `org-{orgId}-{table}` | `postgres_changes *`, schema `cyberguard` | `organization_id=eq.{orgId}` (client-side filter because a publication row filter on a nullable column breaks UPDATEs) |
| `useApi` | — | generic `useApi<T>(apiCall, deps)` → `{data, loading, error, refetch}` with cancellation | — |

**Why polling fallback instead of reconnect storms?** Corporate firewalls, offline dev, and missing Supabase keys would otherwise toast-loop; the 60 s fallback is silent, keeps data fresh, and disposes cleanly when the socket returns (RT-7).

---

## 6. UI/UX Workflows

### Quarantine Triage Workflow

```mermaid
flowchart TB
    ARRIVE(["Realtime arrival (LIVE pill)<br/>or list load (POLLING)"]) --> INSPECT["Inspect: risk gauge · indicators ·<br/>XAI explanation · MITRE tags · review timeline"]
    INSPECT --> D{"Analyst decision"}
    D -->|"Threat confirmed"| KEEP["Keep · release nothing ·<br/>optionally escalate incident"]
    D -->|"False positive"| REL["Release → back to INBOX"]
    D -->|"FP + recurring sender"| TRUST["Release & Trust → sender joins<br/>trusted_senders (future mail recommend-only)"]
    D -->|"Malicious, purge"| DEL["Delete → Gmail trash / permanent<br/>(toggle-gated)"]
    REL & TRUST & DEL --> AUDIT["security_events + audit_logs<br/>(actor: user)"]
    KEEP & AUDIT --> DONE["History recorded on /security-history"]
```

### Incident Lifecycle (state-driven UI)

```mermaid
stateDiagram-v2
    [*] --> open : create incident
    open --> investigating : "Start Investigation" button
    investigating --> contained : "Mark Contained"
    contained --> closed : "Close Incident"
    open --> closed : escalate → critical path
```

`IncidentDetail.tsx` renders the next action from the current status (`NEXT_ACTION` map) and enforces `can('mutate')` + viewer read-only.

### Analysis Page Pattern (all six engines)

Every analysis page follows the same contract: pre-loaded **safe** and **malicious** sample fixtures (e.g. PhishingAnalysis ships `security-alert@micr0soft-verify.xyz` + `http://185.220.101.7/login`; UrlAnalysis contrasts a GitHub deep link with a lookalike domain), input editor → `api.analyze*()` → `RiskGauge` + `IndicatorList` + `ExplanationPanel` + `MitreTags` + `RecommendedActionsPanel`. LogAnalysis adds honest format auto-detection (`detectLogKind`: auth vs network flow) and never auto-fills samples.

---

## 7. Design System

Monochrome SOC aesthetic defined in `theme.ts`:

| Token | Value | Use |
|---|---|---|
| `ACCENT.bg / panel / card` | `#050505 / #0a0a0a / #101010` | Layered dark surfaces |
| `ACCENT.primary / hover` | `#dc2626 / #ef4444` | Actions, active states |
| `ACCENT.border / textPrimary / textSecondary` | `#262626 / #fafafa / #a3a3a3` | Chrome |
| `SEVERITY_RAMP` | safe `#e4e4e7` (dark text) → low `#71717a` → medium `#f87171` (dark text) → high `#dc2626` → critical `#ef4444` (white text + pulse) | Badges, gauges, pills |
| `CHART_COLORS.series` | 6-color red/white/gray ramp | Recharts |

Tailwind 3.3 with custom tokens; icons are lucide-react. Severity color is *always* derived from the score, never hard-coded per page.

---

## 8. Testing & Verification

| Layer | Command | What It Verifies |
|---|---|---|
| Type safety | `npx tsc --noEmit` | Strict compilation of all 40+ pages/services |
| Production build | `npm run build` (`tsc && vite build`) | Optimized asset bundle |
| Unit tests | `npm test` (node test runner, `src/__tests__/realtimeEmails.test.ts`) | Realtime helper logic (dedup, fallback decisions, status chips) |
| In-app docs integrity | `node scripts/check-docs.mjs` (build-time) | 4 invariants: every feature guide carries an example, anchors resolve, audience/minRole tags valid, **every api-reference row matches a real backend route** (43 rows parsed from routers) |
| Manual E2E | RUNBOOK §12 | Live pipeline, LIVE pill, DLQ dashboard |

The realtime store is extracted as a pure, testable unit precisely because the fallback state machine is the riskiest client logic.

---

## 9. FAQ

**Q: Why `fetch` instead of axios?**
The client is 79 lines: auth header injection, one-shot refresh-on-401, and envelope parsing. axios adds bundle weight and an interceptor abstraction the team would not use.

**Q: How does demo/mock mode work?**
`VITE_USE_MOCK=true` swaps `api.ts`'s transport for in-browser mock adapters with pre-calibrated forensic datasets; the topbar shows an amber `DEMO MODE` badge and enforcement actions are disabled/labelled. No backend is required.

**Q: How does the frontend know about org context?**
Every request carries `X-Organization-Id` (from `activeOrganizationId`) when a non-personal org is active; `authStore.can()` gates UI affordances while the backend re-checks every permission.

**Q: Where do Supabase env vars come in?**
`lib/supabaseClient.ts` lazily creates the client only when `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` are both set; hooks no-op silently without them (the polling fallback then always engages).

**Q: Is the route list duplicated anywhere?**
No — `nav.ts` plus the guard components are the single source; the sidebar, `isOrgScopeRoute`, and `ORG_ONLY_ROUTES` all derive from it.
