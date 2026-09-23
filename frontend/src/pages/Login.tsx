import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, AtSign, CheckCircle2, Loader2, Lock, Mail, Shield, User } from 'lucide-react';
import { AuthErrorBanner, AuthErrorInfo } from '../components/common/AuthErrorBanner';
import { AuthApiError, useAuthStore } from '../store/authStore';

type Mode = 'signin' | 'signup' | 'forgot';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
const USERNAME_PATTERN = /^[a-z0-9_.]{3,32}$/;

export default function Login() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const login = useAuthStore((s) => s.login);
  const signUp = useAuthStore((s) => s.signUp);
  const requestPasswordReset = useAuthStore((s) => s.requestPasswordReset);
  const loginWithOAuth = useAuthStore((s) => s.loginWithOAuth);

  const modeParam = searchParams.get('mode');
  const initialMode: Mode =
    modeParam === 'signup' || modeParam === 'forgot' ? modeParam : 'signin';
  const [mode, setMode] = useState<Mode>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [username, setUsername] = useState('');
  const [usernameStatus, setUsernameStatus] = useState<'idle' | 'checking' | 'available' | 'taken' | 'invalid'>('idle');
  const [authError, setAuthError] = useState<AuthErrorInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [oauthLoading, setOauthLoading] = useState<'google' | 'github' | null>(null);

  // Live username availability check (debounced, real backend only).
  useEffect(() => {
    if (mode !== 'signup') return;
    if (!username) {
      setUsernameStatus('idle');
      return;
    }
    if (!USERNAME_PATTERN.test(username)) {
      setUsernameStatus('invalid');
      return;
    }
    setUsernameStatus('checking');
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`${BASE_URL}/auth/username-available?username=${encodeURIComponent(username)}`);
        if (!res.ok) throw new Error('unavailable');
        const data = await res.json();
        setUsernameStatus(data.available ? 'available' : 'taken');
      } catch {
        setUsernameStatus('idle');
      }
    }, 400);
    return () => clearTimeout(t);
  }, [username, mode]);

  const resetMessages = () => {
    setError(null);
    setNotice(null);
    setAuthError(null);
  };

  const switchMode = (newMode: Mode) => {
    resetMessages();
    setMode(newMode);
  };

  const handleBannerSignIn = () => {
    switchMode('signin');
  };

  const handleSignIn = async (emailOverride?: string) => {
    setLoading(true);
    resetMessages();
    try {
      await login(emailOverride || email, password);
      navigate('/dashboard', { replace: true });
    } catch (err: any) {
      if (err instanceof AuthApiError && err.status === 409 && err.code === 'email_exists') {
        setAuthError({
          error: err.code,
          message: err.message,
          hint: err.hint,
        });
      } else {
        setError(err instanceof Error ? err.message : 'Login failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSignUp = async () => {
    resetMessages();
    if (!USERNAME_PATTERN.test(username)) {
      setError('Username must be 3-32 chars: lowercase letters, digits, "_" or "."');
      return;
    }
    if (usernameStatus === 'taken') {
      setError('Username is already taken');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setLoading(true);
    try {
      const { confirmationPending } = await signUp(fullName.trim(), email, password, username.trim().toLowerCase());
      if (confirmationPending) {
        resetMessages();
        setNotice(
          'Verification email sent! Please check your inbox and click the confirmation link to activate your account.'
        );
      } else {
        navigate('/dashboard', { replace: true });
      }
    } catch (err: any) {
      if (err instanceof AuthApiError && err.status === 409 && err.code === 'email_exists') {
        setAuthError({
          error: err.code,
          message: err.message,
          hint: err.hint,
        });
      } else {
        setError(err instanceof Error ? err.message : 'Registration failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleForgot = async () => {
    if (!email) {
      setError('Please enter your email address');
      return;
    }
    setLoading(true);
    try {
      await requestPasswordReset(email);
      resetMessages();
      setNotice('Password reset link sent! Check your inbox for recovery instructions.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not send reset email');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    resetMessages();
    if (mode === 'signin') return handleSignIn();
    if (mode === 'signup') return handleSignUp();
    return handleForgot();
  };

  const handleOAuth = async (provider: 'google' | 'github') => {
    resetMessages();
    setOauthLoading(provider);
    try {
      await loginWithOAuth(provider);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to sign in with ${provider}`);
    } finally {
      setOauthLoading(null);
    }
  };

  const submitLabel =
    mode === 'signin' ? 'Sign In to Workspace' : mode === 'signup' ? 'Create Account' : 'Send Reset Link';

  return (
    <div className="cyber-grid relative flex min-h-screen items-center justify-center bg-zinc-950 px-4 py-12">
      <div className="pointer-events-none fixed left-1/2 top-1/2 h-96 w-96 -translate-x-1/2 -translate-y-1/2 rounded-full bg-red-500/5 blur-3xl" />

      {/* Top back link */}
      <div className="absolute left-6 top-6">
        <Link
          to="/"
          className="flex items-center gap-2 font-mono text-xs text-zinc-400 transition hover:text-red-400"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Overview</span>
        </Link>
      </div>

      <div className="w-full max-w-md">
        <div className="mb-6 flex flex-col items-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-red-500/10 ring-1 ring-red-500/40 shadow-lg shadow-red-500/10">
            <Shield className="h-7 w-7 text-red-400" />
          </div>
          <h1 className="mt-4 font-mono text-2xl font-bold tracking-[0.2em] text-red-400">CYBERGUARD</h1>
          <p className="mt-1.5 text-center text-xs text-zinc-400">
            AI-Powered Cyber Threat & SOAR Command Center
          </p>
        </div>

        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 p-8 shadow-2xl backdrop-blur">
          {/* Mode Switcher Tabs */}
          <div className="mb-5 flex rounded-lg bg-zinc-950 p-1 border border-zinc-800">
            <button
              type="button"
              onClick={() => switchMode('signin')}
              className={`flex-1 rounded-md py-1.5 text-xs font-semibold transition ${
                mode === 'signin' ? 'bg-red-600 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => switchMode('signup')}
              className={`flex-1 rounded-md py-1.5 text-xs font-semibold transition ${
                mode === 'signup' ? 'bg-red-600 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Register
            </button>
            <button
              type="button"
              onClick={() => switchMode('forgot')}
              className={`flex-1 rounded-md py-1.5 text-xs font-semibold transition ${
                mode === 'forgot' ? 'bg-red-600 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Reset
            </button>
          </div>

          {/* Mode status badge */}
          <div className="mb-5 flex items-center justify-between rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs">
            <span className="font-mono text-[11px] font-bold text-red-400">ENTERPRISE SOC MODE</span>
            <span className="text-[10px] text-zinc-400">Supabase Auth Connected</span>
          </div>

          {/* OAuth Buttons (shown for signin & signup) */}
          {mode !== 'forgot' && (
            <>
              <div className="space-y-2.5">
                <button
                  type="button"
                  onClick={() => handleOAuth('google')}
                  disabled={loading || oauthLoading !== null}
                  className="flex w-full items-center justify-center gap-3 rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 px-4 text-xs font-semibold text-zinc-200 shadow-sm transition hover:border-zinc-700 hover:bg-zinc-800/60 disabled:opacity-60"
                >
                  {oauthLoading === 'google' ? (
                    <Loader2 className="h-4 w-4 animate-spin text-red-400" />
                  ) : (
                    <svg className="h-4 w-4" viewBox="0 0 24 24">
                      <path
                        fill="#4285F4"
                        d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"
                      />
                      <path
                        fill="#34A853"
                        d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.33 24 12 24z"
                      />
                      <path
                        fill="#FBBC05"
                        d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 9.98 0 12s.45 3.82 1.25 5.42l4.03-3.15z"
                      />
                      <path
                        fill="#EA4335"
                        d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
                      />
                    </svg>
                  )}
                  <span>Continue with Google</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleOAuth('github')}
                  disabled={loading || oauthLoading !== null}
                  className="flex w-full items-center justify-center gap-3 rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 px-4 text-xs font-semibold text-zinc-200 shadow-sm transition hover:border-zinc-700 hover:bg-zinc-800/60 disabled:opacity-60"
                >
                  {oauthLoading === 'github' ? (
                    <Loader2 className="h-4 w-4 animate-spin text-red-400" />
                  ) : (
                    <svg className="h-4 w-4 fill-zinc-200" viewBox="0 0 24 24">
                      <path
                        fillRule="evenodd"
                        clipRule="evenodd"
                        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                      />
                    </svg>
                  )}
                  <span>Continue with GitHub</span>
                </button>
              </div>

              <div className="relative my-6">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-zinc-800" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-zinc-900 px-2 font-mono text-[10px] tracking-wider text-zinc-500">
                    OR CONTINUE WITH EMAIL
                  </span>
                </div>
              </div>
            </>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'signup' && (
              <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">
                  Username
                </label>
                <div className="relative">
                  <AtSign className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value.toLowerCase())}
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/60 focus:ring-1 focus:ring-red-500/40"
                    placeholder="alex.mercer"
                  />
                </div>
                {usernameStatus === 'checking' && (
                  <p className="mt-1 font-mono text-[10px] text-zinc-500">Checking availability...</p>
                )}
                {usernameStatus === 'available' && (
                  <p className="mt-1 flex items-center gap-1 font-mono text-[10px] text-emerald-400">
                    <CheckCircle2 className="h-3 w-3" /> {username} is available
                  </p>
                )}
                {usernameStatus === 'taken' && (
                  <p className="mt-1 font-mono text-[10px] text-red-400">{username} is already taken</p>
                )}
                {usernameStatus === 'invalid' && (
                  <p className="mt-1 font-mono text-[10px] text-zinc-500">
                    3-32 chars: lowercase letters, digits, "_" or "."
                  </p>
                )}
              </div>
            )}

            {mode === 'signup' && (
              <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">
                  Full Name
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    type="text"
                    required
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/60 focus:ring-1 focus:ring-red-500/40"
                    placeholder="Alex Mercer"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">
                {mode === 'signin' ? 'Email or Username' : 'Email Address'}
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                <input
                  type={mode === 'signin' ? 'text' : 'email'}
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/60 focus:ring-1 focus:ring-red-500/40"
                  placeholder={mode === 'signin' ? 'you@company.com or alex.mercer' : 'analyst@yourcompany.com'}
                />
              </div>
            </div>

            {mode !== 'forgot' && (
              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <label className="block text-xs font-medium uppercase tracking-wider text-zinc-400">
                    Password
                  </label>
                  {mode === 'signin' && (
                    <button
                      type="button"
                      onClick={() => switchMode('forgot')}
                      className="text-[11px] text-red-400 transition hover:text-red-300"
                    >
                      Forgot password?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/60 focus:ring-1 focus:ring-red-500/40"
                    placeholder="••••••••"
                  />
                </div>
              </div>
            )}

            {mode === 'signup' && (
              <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">
                  Confirm Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    type="password"
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition focus:border-red-500/60 focus:ring-1 focus:ring-red-500/40"
                    placeholder="••••••••"
                  />
                </div>
              </div>
            )}

            {notice && (
              <div className="flex items-start gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-300">
                <CheckCircle2 className="h-4 w-4 flex-shrink-0 text-emerald-400 mt-0.5" />
                <span>{notice}</span>
              </div>
            )}

            <AuthErrorBanner
              errorInfo={authError}
              onAction={handleBannerSignIn}
            />

            {error && !authError && (
              <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-400">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || oauthLoading !== null}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-red-600 py-2.5 text-sm font-bold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500 disabled:opacity-60"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {loading ? 'Processing...' : submitLabel}
            </button>
          </form>

          {mode === 'forgot' && (
            <div className="mt-4 text-center">
              <button
                type="button"
                onClick={() => switchMode('signin')}
                className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-red-400"
              >
                <ArrowLeft className="h-3.5 w-3.5" /> Return to sign in
              </button>
            </div>
          )}
        </div>

        <p className="mt-6 text-center text-[11px] text-zinc-500">
          CyberGuard SOC Platform • End-to-End Encrypted Sessions • Multi-Tenant RBAC
        </p>
      </div>
    </div>
  );
}
