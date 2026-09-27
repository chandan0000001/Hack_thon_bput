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
  const DEADLINE_MS = 10000; // per callback-path visit, not per document
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
        // The background also closes sender.tab; window.close() is the
        // fallback that covers contexts where sender.tab is unavailable.
        raw.runtime.sendMessage(payload, () => {
          try { window.close(); } catch (e) { /* background closes the tab */ }
        });
        setTimeout(() => {
          try { window.close(); } catch (e) { /* already closing */ }
        }, 500);
      }
    } else if (Date.now() - callbackSince > DEADLINE_MS) {
      clearInterval(timer);
      // No handoff arrived; leave the page so its error state stays visible.
    }
  }, POLL_MS);
})();
