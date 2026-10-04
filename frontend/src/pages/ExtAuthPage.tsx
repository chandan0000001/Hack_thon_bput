import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getSupabase } from '../lib/supabaseClient';
import Login from './Login';

/**
 * EXT-P1 — universal extension sign-in entry (opened by the CyberGuard
 * browser extension's popup).
 *
 * With a live website session this redirects straight to /ext/callback;
 * signed-out visitors get the normal personal login (Login.tsx) and its
 * `next` redirect returns them to /ext/callback once auth succeeds.
 */
function ExtShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <span className="inline-flex items-center gap-2 font-mono text-sm text-zinc-400">
            <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-red-600 text-[11px] font-bold text-white">
              CG
            </span>
            CyberGuard — Extension Sign-In
          </span>
        </div>
        {children}
      </div>
    </div>
  );
}

export default function ExtAuthPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const state = searchParams.get('state') ?? '';
  const [checking, setChecking] = useState(true);
  // Live web session: ask before reusing it. A silent auto-handoff here made
  // "sign out (extension) → sign in" skip the credential form entirely,
  // because the WEBSITE's Supabase session survives the extension's sign-out.
  const [existingEmail, setExistingEmail] = useState<string | null>(null);

  const callbackNext = `/ext/callback?state=${encodeURIComponent(state)}&v=1`;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const supabase = getSupabase();
      if (supabase) {
        const { data } = await supabase.auth.getSession();
        if (!cancelled && data.session) {
          setExistingEmail(data.session.user?.email ?? 'your account');
          return;
        }
      }
      if (!cancelled) setChecking(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Signed-out visitors get the normal personal login; hand Login its `next`
  // via the URL (same-app path, guarded in Login.tsx) so a successful sign-in
  // returns into the extension flow instead of /dashboard. Also stash the
  // callback in localStorage (30-min TTL): flows that leave the page — OAuth
  // provider bounces, email-verification links — lose the URL param, and the
  // stash is the only thing that routes the user back into the handoff.
  useEffect(() => {
    if (checking || searchParams.get('next')) return;
    const params = new URLSearchParams(searchParams);
    params.set('next', callbackNext);
    setSearchParams(params, { replace: true });
  }, [checking, searchParams, callbackNext, setSearchParams]);

  useEffect(() => {
    try {
      localStorage.setItem(
        'cyberguard_ext_auth_next',
        JSON.stringify({ next: callbackNext, at: Date.now() }),
      );
    } catch {
      // ignore — URL ?next= still covers the common path
    }
  }, [callbackNext]);

  if (checking) {
    return (
      <ExtShell>
        <p className="text-center text-sm text-zinc-400">Checking sign-in status…</p>
      </ExtShell>
    );
  }

  if (existingEmail) {
    return (
      <ExtShell>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-6 text-center">
          <p className="text-sm text-zinc-300">
            You are signed in on the web as
          </p>
          <p className="mt-1 font-mono text-sm text-zinc-100">{existingEmail}</p>
          <button
            type="button"
            onClick={() => navigate(callbackNext, { replace: true })}
            className="mt-5 w-full rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
          >
            Connect the extension as this account
          </button>
          <button
            type="button"
            onClick={async () => {
              const supabase = getSupabase();
              if (supabase) await supabase.auth.signOut().catch(() => undefined);
              setExistingEmail(null);
              setChecking(false);
            }}
            className="mt-2 w-full rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
          >
            Use a different account
          </button>
        </div>
      </ExtShell>
    );
  }

  return (
    <ExtShell>
      <Login />
    </ExtShell>
  );
}
