# Firefox smoke checklist (EXT-P1) — manual, do not automate

Run from `browser-extension/`:

```bash
npm run build
npx web-ext run --source-dir dist/firefox --url http://localhost:5173/login
```

Prerequisites: backend on :8000, Vite dev server on :5173, demo user seeded
(`demo@cyberguard.local` / `demo1234!`).

| # | Step | Expected |
|---|------|----------|
| 1 | `web-ext run` starts | Firefox opens; no console errors from the extension |
| 2 | about:debugging → This Firefox → Temporary Extensions | "CyberGuard SOC" listed, id `cyberguard-soc@cyberguard.local` |
| 3 | Click the CyberGuard SOC toolbar icon | Popup renders signed-out: shield, "Sign In to CyberGuard" |
| 4 | Click "Sign In to CyberGuard" | New tab opens `http://localhost:5173/ext/auth?state=<uuid>&v=1` |
| 5 | Personal login form appears (already-signed-in session → jumps straight to /ext/callback) | themed dark page |
| 6 | Sign in with demo credentials | tab navigates to `/ext/callback?state=…`, shows "Completing extension sign-in…", then the tab closes itself |
| 7 | Reopen the popup | green check, "Authenticated", `demo@cyberguard.local`, "Connected to CyberGuard SOC", [Open Web Console] [Sign Out] |
| 8 | Reload the page / reopen popup | still Authenticated (storage.local persistence) |
| 9 | Click [Open Web Console] | new tab → `http://localhost:5173/dashboard` |
| 10 | Click [Sign Out] | popup back to signed-out shield state |
| 11 | `web-ext lint --source-dir dist/firefox` | 0 errors, 0 warnings |

Notes:
- The first-run `moz-extension://` UUID is random; background fetches to the
  API/Supabase are covered by `host_permissions` (no CORS entry needed).
- If step 7 shows "identity unavailable", the backend lacks the extension
  origin — check `EXT_CORS_ORIGINS` in `backend/.env`.
