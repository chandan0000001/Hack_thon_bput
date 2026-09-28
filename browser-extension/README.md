# CyberGuard SOC — Browser Extension (EXT-P1)

Cross-browser WebExtension scaffold: Chromium and Firefox builds come from one
shared source in `src/`. P1 ships the universal auth flow; P2 adds the three
analyzers (Scan URL, Scan Email, Detect Deepfake) calling the website's
`/analysis/url`, `/analysis/email` and `/analysis/media` contracts with the
stored Bearer token (401 → background refresh → retry → sign-out on failure).

P3 adds the on-page scanner (`lib/detect.js` + `content/scanner.js`): a
MutationObserver debounced to 500ms detects links/URLs, webmail bodies
(Gmail `.ii`, Outlook `[aria-label="Message body"]`, ProtonMail
`.message-content`) and >200×200 images on every http(s) page. Detection is
local-only — a floating pill (`content/pill.js`) shows
"{N} links · {M} emails · {K} images detected — [Analyze?]" and nothing is
sent until the click. The batch goes to the background
(`ANALYZE_BATCH` → api-client → `BATCH_RESULTS`) and the results overlay
(`content/overlay.js`, summary + per-detection cards, [Open in popup]
re-opens the popup's URL view pre-filled). Settings in `chrome.storage.local`:
`scan_url` / `scan_email` / `scan_image`, `scan_allowlist` (default empty =
all domains), `scan_max_detections` (default 20). Web stores and iframes are
excluded.

## Layout

```
browser-extension/
  build.mjs            one source -> dist/chromium (MV3 service worker)
                                       -> dist/firefox  (MV3 event page)
  src/
    manifest.base.json target-neutral manifest; build.mjs applies per-target deltas
    background.js      auth owner: nonce, fragment handoff, token refresh
    popup/             popup.html + popup.js + theme.css (signed-out/authenticated UI)
    content/           callback-bridge.js (${WEB}/ext/callback -> background)
    lib/               browser-adapter.js (browser/chrome promisification)
                       auth.js (pure, node-testable auth primitives)
                       api-client.js (/auth/me stub — scanner endpoints in P3)
                       path-gate.js (exact /ext/callback enforcement)
    theme.css          website design tokens (quoted from frontend/src/theme.ts,
                       tailwind.config.js, index.css)
  tests/               node --test suite (48 checks, 20 files)
  e2e/                 playwright-auth.mjs (P1 live auth walkthrough)
                       playwright-analyzers.mjs (P2 analyzer walkthrough, mocked API)
                       playwright-scanner.mjs (P3 scanner walkthrough, mock API server)
```

## Build & verify

```bash
npm install          # web-ext (lint) only — no runtime deps
npm run build        # emits dist/chromium + dist/firefox, validates manifests
npm test             # node --test tests/  (includes web-ext lint per target)
npm run lint         # standalone web-ext lint, both targets
```

Build config comes from `EXT_WEB_ORIGIN`, `EXT_API_BASE_URL`, `EXT_SUPABASE_URL`,
`EXT_SUPABASE_ANON_KEY` env vars, falling back to `frontend/.env.local`
(`VITE_*`), falling back to dev defaults (web `http://localhost:5173`, API
`http://localhost:8000/api/v1`).

## Stable dev identities

- Chromium: the manifest pins an RSA `key` (see `build.mjs`), so the unpacked
  extension always loads as `chrome-extension://mkhcpikficaipogflekjkoiplegbeaji`. That origin
  belongs in the backend's `EXT_CORS_ORIGINS` (see `backend/.env.example`).
- Firefox: gecko id `cyberguard-soc@cyberguard.local`. The `moz-extension://`
  UUID is random per install; background fetches are covered by
  `host_permissions`, so no CORS entry is needed for the auth flow.

## Auth flow (no identity API)

1. Popup (signed out) → background mints a single-use nonce (storage.session)
   → popup opens `${WEB}/ext/auth?state=<nonce>&v=1`.
2. `/ext/auth`: live website session → straight to `/ext/callback`; otherwise
   the normal personal login (`Login.tsx?next=/ext/callback?state=…`).
3. `/ext/callback` writes the Supabase session into `location.hash`
   (fragment-only — never a query string, never a server log) and renders
   "Completing extension sign-in…".
4. The content bridge (path-gated to exactly `/ext/callback`) forwards the
   raw hash to the background and closes the tab.
5. Background verifies the nonce single-use, persists
   `{access_token, refresh_token, expires_at, email}` in `storage.local`, and
   arms a refresh alarm at `expires_at - 60s`. Terminal refresh failures
   (400/401/403) drop the session back to signed-out.
