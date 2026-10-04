/*
 * CyberGuard extension — /ext/callback content bridge.
 *
 * Registered for the whole website origin (match patterns cannot pin a
 * path). lib/path-gate.js rejects every path except the EXACT
 * /ext/callback. Because the website is a client-side-routed SPA, the
 * document that loads /ext/auth may later navigate to /ext/callback without
 * a new document load — so the bridge watches pathname transitions, but
 * only ever acts while the exact-path gate holds. The page writes the
 * session into location.hash (fragment-only handoff — never a query
 * string, never a server log); this bridge forwards it to the background
 * worker and closes the tab.
 */
(function () {
  'use strict';

  const gate = globalThis.CyberGuardExt && globalThis.CyberGuardExt.isCallbackPath;
  if (!gate) return;
  const raw = globalThis.browser ?? globalThis.chrome;
  if (!raw || !raw.runtime || !raw.runtime.sendMessage) return;

  const POLL_MS = 100;
  const DEADLINE_MS = 30000; // per callback-path visit, not per document
  let forwarded = false;
  let callbackSince = null;

  const timer = setInterval(() => {
    globalThis.__cgCallbackPollTimer = timer; // exposed so tests can stop the poll early

    if (!gate(location.pathname)) {
      callbackSince = null;
      return;
    }
    if (callbackSince === null) callbackSince = Date.now();

    const hash = location.hash || '';
    if (hash.includes('access_token=')) {
      if (!forwarded) {
        forwarded = true;
        clearInterval(timer);
        const payload = { type: 'EXT_AUTH', hash };
        raw.runtime.sendMessage(payload, (res) => {
          // Surface the handoff result on the page so the user sees
          // success/error instead of a tab that silently vanishes or hangs.
          try {
            window.dispatchEvent(new CustomEvent('cg:ext-auth-result', {
              detail: res || { ok: false, error: 'no_response' },
            }));
          } catch (e) { /* page is not the CyberGuard callback app */ }
          if (res && res.ok) {
            // Give the success page a moment to be visible, then close.
            // The background also removes the tab as a fallback.
            setTimeout(() => {
              try { window.close(); } catch (e) { /* background closes it */ }
            }, 2000);
          }
        });
      }
    } else if (Date.now() - callbackSince > DEADLINE_MS) {
      clearInterval(timer);
      // No handoff arrived; leave the page so its error state stays visible.
    }
  }, POLL_MS);
})();
