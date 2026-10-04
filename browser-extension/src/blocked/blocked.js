/*
 * CyberGuard block page — hydrates from query params set by the background
 * worker. Classic script (no bundling); runs only on the extension's own
 * blocked.html page.
 */
(function () {
  'use strict';
  const params = new URLSearchParams(location.search);
  const get = (k) => params.get(k) || '—';

  const hostEl = document.getElementById('cg-host');
  const scoreEl = document.getElementById('cg-score');
  const sevEl = document.getElementById('cg-severity');
  const reasonsEl = document.getElementById('cg-reasons');
  const proceedEl = document.getElementById('cg-proceed');
  const detailsEl = document.getElementById('cg-details');
  const backEl = document.getElementById('cg-back');

  let blockedUrl = params.get('url') || '';
  try {
    hostEl.textContent = new URL(blockedUrl).hostname;
  } catch (e) {
    hostEl.textContent = blockedUrl || '—';
  }
  scoreEl.textContent = get('score');
  sevEl.textContent = String(get('severity')).toUpperCase();

  let reasons = [];
  try { reasons = JSON.parse(params.get('reasons') || '[]'); } catch (e) { /* none */ }
  if (!Array.isArray(reasons) || !reasons.length) reasons = ['Combined Stage-1 + Stage-2 evidence met the BLOCK policy'];
  for (const reason of reasons) {
    const li = document.createElement('li');
    li.textContent = String(reason);
    reasonsEl.appendChild(li);
  }

  backEl.addEventListener('click', () => {
    // The worker pushed this page right after the blocked target, so session
    // history is […, target, blockedPage]: a single back() re-lands on the
    // blocked URL and gets re-blocked — an infinite loop. Skip past the
    // target entry; if the target was this tab's first entry, leave history.
    if (history.length > 2) history.go(-2);
    else location.replace('about:blank');
  });

  // The user always owns the risk: one click goes to the blocked site.
  proceedEl.href = blockedUrl || '#';

  // Deep link into the dashboard URL view when an origin is configured.
  const apiBase = params.get('apiBase') || '';
  try {
    if (apiBase) {
      const origin = new URL(apiBase).origin;
      detailsEl.href = `${origin.replace(':8000', ':5173')}/url-analysis?url=${encodeURIComponent(blockedUrl)}`;
      detailsEl.target = '_blank';
      detailsEl.rel = 'noopener';
    } else {
      detailsEl.remove();
    }
  } catch (e) { detailsEl.remove(); }
})();
