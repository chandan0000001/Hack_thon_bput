/** MEMBER-INVITE-P2: pure helpers for the accept-invitation page (node:test
 * importable — no React/JSX here). */

export type AcceptErrorKind = 'invalid' | 'expired' | 'mismatch' | 'generic';

/** Map the backend accept-flow failures to user-facing copy (F2):
 * 404 invalid/used, 410 expired/revoked, 403 email mismatch. */
export function mapAcceptError(status: number | undefined, message: string): {
  kind: AcceptErrorKind;
  text: string;
} {
  if (status === 404) return { kind: 'invalid', text: 'Invalid or used invitation link.' };
  if (status === 410) return { kind: 'expired', text: 'This invitation has expired.' };
  if (status === 403) {
    return { kind: 'mismatch', text: 'This invitation was sent to a different email address.' };
  }
  return { kind: 'generic', text: message || 'Failed to accept the invitation.' };
}

/** Post-acceptance landing: the org's project selector (the workspace root for
 * the joined org; there is no /org/{id}/dashboard route). */
export function acceptRedirectPath(orgId: string): string {
  return `/org/${encodeURIComponent(orgId)}/projects`;
}

/** Unauthenticated visitors are bounced to org login with a `next` hop back to
 * this page (Login honors `next` only for same-app paths). */
export function loginRedirectPath(token: string): string {
  return `/login?mode=org&next=${encodeURIComponent(`/auth/accept-invite?token=${encodeURIComponent(token)}`)}`;
}

/** A token param is required and must look plausible before we call the API. */
export function hasUsableToken(token: string | null): boolean {
  return typeof token === 'string' && token.trim().length >= 16;
}
