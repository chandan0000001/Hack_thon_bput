import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { getSupabase } from '../lib/supabaseClient';

/**
 * EXT-P1 — extension sign-in callback.
 *
 * Reads the Supabase session from this origin's localStorage and hands the
 * tokens to the extension via location.hash ONLY — the fragment never
 * reaches a server, proxy, or access log. The /ext/callback content bridge
 * picks the fragment up, forwards it to the background worker, and reports
 * the outcome back via a `cg:ext-auth-result` DOM event so this page can
 * show a real success/error state instead of spinning forever.
 */
type Phase = 'working' | 'success' | 'error';

export default function ExtCallbackPage() {
  const [searchParams] = useSearchParams();
  const state = searchParams.get('state') ?? '';
  const [phase, setPhase] = useState<Phase>('working');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const supabase = getSupabase();
      if (!supabase) {
        if (!cancelled) {
          setPhase('error');
          setError('Sign-in bridge unavailable (Supabase not configured).');
        }
        return;
      }
      const { data } = await supabase.auth.getSession();
      const session = data.session;
      if (!session) {
        if (!cancelled) {
          setPhase('error');
          setError('No active session. Please start sign-in again from the extension.');
        }
        return;
      }
      if (cancelled) return;
      const params = new URLSearchParams({
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        expires_at: String(session.expires_at ?? Math.floor(Date.now() / 1000) + 3600),
        state,
        v: '1',
      });
      // Fragment-only handoff (#... is never sent to any server).
      location.hash = params.toString();
    })();
    return () => {
      cancelled = true;
    };
  }, [state]);

  useEffect(() => {
    const onResult = (e: Event) => {
      const detail = (e as CustomEvent<{ ok?: boolean; error?: string }>).detail || {};
      if (detail.ok) {
        setPhase('success');
      } else {
        setPhase('error');
        const reason = detail.error || 'no_response';
        setError(
          reason === 'no_pending_auth' || reason === 'state_mismatch'
            ? 'This sign-in was not started by the extension (or it expired). Please click Sign In in the extension again.'
            : `Extension handoff failed (${reason}).`,
        );
      }
    };
    window.addEventListener('cg:ext-auth-result', onResult);
    return () => window.removeEventListener('cg:ext-auth-result', onResult);
  }, []);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 flex items-center justify-center px-4">
      <div className="text-center max-w-md">
        {phase === 'success' ? (
          <>
            <div
              className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-600/20 text-2xl text-emerald-400"
              aria-hidden="true"
            >
              ✓
            </div>
            <p className="text-lg font-medium text-emerald-400">
              Signed in to CyberGuard successfully
            </p>
            <p className="mt-2 text-sm text-zinc-400">
              The extension is connected. This tab will close itself — you can close it too.
            </p>
          </>
        ) : phase === 'error' ? (
          <>
            <p className="text-sm text-red-500">{error}</p>
            <Link to="/dashboard" className="mt-4 inline-block text-sm text-zinc-400 underline">
              Go to CyberGuard
            </Link>
          </>
        ) : (
          <p className="text-sm text-zinc-300">Completing extension sign-in…</p>
        )}
      </div>
    </div>
  );
}
