import { useEffect, useRef, useState } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle2, Loader2, MailQuestion, ShieldAlert } from 'lucide-react';
import { orgApi } from '../services/orgApi';
import { ApiError } from '../services/http';
import { useAuthStore } from '../store/authStore';
import {
  acceptRedirectPath,
  hasUsableToken,
  loginRedirectPath,
  mapAcceptError,
  type AcceptErrorKind,
} from './acceptInvitationHelpers';

type Phase =
  | { state: 'verifying' }
  | { state: 'success'; orgId: string; orgName: string; role: string }
  | { state: 'error'; kind: AcceptErrorKind; text: string };

/**
 * MEMBER-INVITE-P2: /auth/accept-invite?token={token}
 * Unauthenticated visitors are redirected to org login (with a `next` hop
 * back); authenticated users redeem the token immediately. Centered dark
 * card with red accents, matching the auth pages.
 */
export default function AcceptInvitationPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const hydrated = useAuthStore((s) => s.hydrated);

  const [phase, setPhase] = useState<Phase>({ state: 'verifying' });
  const started = useRef(false);

  useEffect(() => {
    if (!hydrated || !isAuthenticated) return; // wait for session hydration
    if (started.current) return;
    started.current = true;

    if (!hasUsableToken(token)) {
      setPhase({ state: 'error', kind: 'invalid', text: 'Invalid or used invitation link.' });
      return;
    }

    setPhase({ state: 'verifying' });
    orgApi
      .acceptInvitation(token!.trim())
      .then((res) => {
        setPhase({ state: 'success', orgId: res.organization_id, orgName: res.organization_name, role: res.role });
        // Brief moment on the success card, then land in the joined org.
        window.setTimeout(() => navigate(acceptRedirectPath(res.organization_id), { replace: true }), 1600);
      })
      .catch((err) => {
        const status = err instanceof ApiError ? err.status : undefined;
        const message = err instanceof Error ? err.message : 'Failed to accept the invitation.';
        setPhase({ state: 'error', ...mapAcceptError(status, message) });
      });
  }, [hydrated, isAuthenticated, token, navigate]);

  // Not signed in (and session hydration finished): bounce to org login and
  // come straight back here after sign-in.
  if (hydrated && !isAuthenticated) {
    return <Navigate to={loginRedirectPath(token ?? '')} replace />;
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div
        data-testid="accept-invite-card"
        className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-8 text-center shadow-2xl"
      >
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-red-500/30 bg-red-500/10">
          {phase.state === 'success' ? (
            <CheckCircle2 className="h-6 w-6 text-emerald-400" />
          ) : phase.state === 'error' ? (
            <ShieldAlert className="h-6 w-6 text-red-400" />
          ) : (
            <MailQuestion className="h-6 w-6 text-red-400" />
          )}
        </div>

        {phase.state === 'verifying' && (
          <>
            <h1 className="text-lg font-semibold text-zinc-100" data-testid="accept-title">
              Verifying invitation...
            </h1>
            <p className="mt-2 text-xs text-zinc-400">Checking your organization invitation.</p>
            <Loader2 className="mx-auto mt-5 h-5 w-5 animate-spin text-red-500" data-testid="accept-spinner" />
          </>
        )}

        {phase.state === 'success' && (
          <>
            <h1 className="text-lg font-semibold text-zinc-100" data-testid="accept-title">
              Welcome to {phase.orgName || 'your organization'}!
            </h1>
            <p className="mt-2 text-xs text-zinc-400" data-testid="accept-subtitle">
              You joined as <span className="font-mono text-zinc-300">{phase.role}</span>. Taking you to the
              workspace…
            </p>
          </>
        )}

        {phase.state === 'error' && (
          <>
            <h1 className="text-lg font-semibold text-zinc-100" data-testid="accept-title">
              Invitation could not be accepted
            </h1>
            <p className="mt-2 text-xs text-red-400" data-testid="accept-error">
              {phase.text}
            </p>
            <Link
              to="/org/select"
              className="mt-6 inline-flex items-center justify-center rounded-lg bg-red-600 px-4 py-2 text-xs font-bold text-white transition hover:bg-red-500"
            >
              Go to sign in
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
