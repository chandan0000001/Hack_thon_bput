import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { getSupabase } from '../lib/supabaseClient';

/**
 * EXT-P1 — extension sign-in callback.
 *
 * Reads the Supabase session from this origin's localStorage and hands the
 * tokens to the extension via location.hash ONLY — the fragment never
 * reaches a server, proxy, or access log. The /ext/callback content bridge
 * picks the fragment up, forwards it to the background worker, and closes
 * the tab.
 */
export default function ExtCallbackPage() {
  const [searchParams] = useSearchParams();
  const state = searchParams.get('state') ?? '';
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const supabase = getSupabase();
      if (!supabase) {
        if (!cancelled) setError('Sign-in bridge unavailable (Supabase not configured).');
        return;
      }
      const { data } = await supabase.auth.getSession();
      const session = data.session;
      if (!session) {
        if (!cancelled) setError('No active session. Please start sign-in again from the extension.');
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

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 flex items-center justify-center px-4">
      <div className="text-center">
        {error ? (
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
