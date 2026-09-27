/*
 * CyberGuard extension — callback path gate.
 *
 * The callback content script MUST only ever act on the website's exact
 * /ext/callback path. Match patterns in the manifest cannot pin a path, so
 * this pure predicate is the enforcement point (unit-tested: /ext/callback2,
 * sub-paths and any other path are rejected).
 */
(function (global) {
  'use strict';

  const CALLBACK_PATH = '/ext/callback';
  // Anchored exact match: no prefix, no suffix, no trailing segments.
  const CALLBACK_PATH_RE = /^\/ext\/callback$/;

  function isCallbackPath(pathname) {
    return typeof pathname === 'string' && CALLBACK_PATH_RE.test(pathname);
  }

  global.CyberGuardExt = global.CyberGuardExt || {};
  global.CyberGuardExt.CALLBACK_PATH = CALLBACK_PATH;
  global.CyberGuardExt.isCallbackPath = isCallbackPath;
})(globalThis);
