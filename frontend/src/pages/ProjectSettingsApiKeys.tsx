import { useEffect, useState } from 'react';
import { Eye, KeyRound, Loader2, ShieldCheck } from 'lucide-react';
import CopyButton from '../components/common/CopyButton';
import { useCopyFlash } from '../hooks/useCopyFlash';
import { orgApi, type ApiKeyRole, type ProjectApiKey } from '../services/orgApi';
import { ApiError } from '../services/http';

const SLOTS: { role: ApiKeyRole; title: string; blurb: string }[] = [
  { role: 'master', title: 'Master key', blurb: 'All gateway actions: ingest, analyze, enforce' },
  { role: 'viewer', title: 'View-only key', blurb: 'Read-only audit access; write actions reject with 403' },
];

/**
 * ORG-SETTINGS-P5: API Keys section — two-slot master/viewer cards +
 * gateway reference. Admins get key data; non-admins get a single info card
 * and the keys endpoint is never called for them.
 */
export default function ProjectSettingsApiKeys({
  orgId,
  projectId,
  projectSlug,
}: {
  orgId: string;
  projectId: string;
  projectSlug: string;
}) {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const [keys, setKeys] = useState<ProjectApiKey[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Generate (plaintext-once) modal state
  const [generatingRole, setGeneratingRole] = useState<ApiKeyRole | null>(null);
  const [creating, setCreating] = useState(false);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [savedConfirmed, setSavedConfirmed] = useState(false);
  const [generateError, setGenerateError] = useState<string | null>(null);

  // Revoke confirm modal state
  const [revokeTarget, setRevokeTarget] = useState<ProjectApiKey | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const [busyRole, setBusyRole] = useState<ApiKeyRole | null>(null);
  const { copiedKey, copy } = useCopyFlash();

  const gatewayUrl = `https://${window.location.host}/api/v1/p/${projectSlug}/gateway`;
  const curlExample = [
    `curl -X POST "${gatewayUrl}" \\`,
    `  -H "Authorization: Bearer <your-master-key>" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{"action": "analyze_log", "data": {"log_line": "Failed password for admin from 203.0.113.7"}}'`,
  ].join('\n');

  // Role resolution first; the keys endpoint is touched only for admins (K3).
  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const org = await orgApi.getOrg(orgId);
        if (!mounted) return;
        setIsAdmin(org.role === 'admin');
        if (org.role !== 'admin') return;
        const rows = await orgApi.listKeys(orgId, projectId);
        if (!mounted) return;
        setKeys(rows);
      } catch (err) {
        if (mounted) setLoadError(err instanceof Error ? err.message : 'Failed to load API keys');
      }
    };
    load();
    return () => {
      mounted = false;
    };
  }, [orgId, projectId]);

  const activeKeyFor = (role: ApiKeyRole): ProjectApiKey | null =>
    (keys ?? []).find((k) => k.role === role && k.status === 'active') ?? null;

  const generate = async (role: ApiKeyRole) => {
    setGeneratingRole(role);
    setCreating(true);
    setPlaintext(null);
    setSavedConfirmed(false);
    setGenerateError(null);
    try {
      const name = `${role === 'master' ? 'Master' : 'View-only'} key · ${new Date().toLocaleDateString()}`;
      const created = await orgApi.createKey(orgId, projectId, name, role);
      setPlaintext(created.api_key);
    } catch (err) {
      setGenerateError(err instanceof ApiError ? err.message : 'Failed to generate key');
    } finally {
      setCreating(false);
    }
  };

  const closeGenerateModal = () => {
    // Plaintext is intentionally dropped here — it can never be shown again.
    setGeneratingRole(null);
    setPlaintext(null);
    setSavedConfirmed(false);
    setGenerateError(null);
    setBusyRole(generatingRole);
    orgApi
      .listKeys(orgId, projectId)
      .then((rows) => setKeys(rows))
      .catch(() => undefined)
      .finally(() => setBusyRole(null));
  };

  const confirmRevoke = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    setRevokeError(null);
    try {
      await orgApi.revokeKey(orgId, projectId, revokeTarget.id);
      setRevokeTarget(null);
      setBusyRole(revokeTarget.role);
      const rows = await orgApi.listKeys(orgId, projectId);
      setKeys(rows);
    } catch (err) {
      setRevokeError(err instanceof ApiError ? err.message : 'Failed to revoke key');
    } finally {
      setRevoking(false);
      setBusyRole(null);
    }
  };

  // ── Non-admin: info card only, zero key data/buttons ────────────────────
  if (isAdmin === false) {
    return (
      <div className="mt-6 space-y-5">
        <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5" data-testid="apikeys-info-card">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-red-400" />
            <h3 className="text-sm font-semibold text-zinc-100">API keys</h3>
          </div>
          <p className="mt-2 text-xs text-zinc-400" data-testid="apikeys-info-text">
            API keys are managed by organization admins.
          </p>
        </section>
        <GatewayRow
          gatewayUrl={gatewayUrl}
          curlExample={curlExample}
          copiedKey={copiedKey}
          copy={copy}
        />
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="mt-6 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-400">
        {loadError}
      </div>
    );
  }

  return (
    <div className="mt-6 space-y-5">
      {/* ── Two-slot key cards ──────────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {SLOTS.map(({ role, title, blurb }) => {
          const active = activeKeyFor(role);
          const busy = busyRole === role || keys === null;
          return (
            <section
              key={role}
              className="flex flex-col rounded-xl border border-zinc-800 bg-zinc-900/60 p-5"
              data-testid={`key-card-${role}`}
            >
              <div className="flex items-center gap-2">
                {role === 'master' ? (
                  <ShieldCheck className="h-4 w-4 text-red-400" />
                ) : (
                  <Eye className="h-4 w-4 text-red-400" />
                )}
                <h3 className="text-sm font-semibold uppercase tracking-wide text-zinc-100">
                  {role === 'master' ? 'Master key' : title}
                </h3>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-zinc-400">{blurb}</p>

              <div className="mt-4 flex-1">
                {busy ? (
                  <div className="flex h-20 items-center justify-center">
                    <Loader2 className="h-4 w-4 animate-spin text-zinc-500" />
                  </div>
                ) : active ? (
                  /* ── Active state ── */
                  <div className="space-y-3" data-testid={`key-active-${role}`}>
                    <div>
                      <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Key prefix</p>
                      <p className="mt-0.5 font-mono text-xs text-zinc-200">{active.key_prefix}</p>
                    </div>
                    <div className="flex flex-wrap gap-4">
                      <div>
                        <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Last used</p>
                        <p className="mt-0.5 text-xs text-zinc-300">
                          {active.last_used_at ? new Date(active.last_used_at).toLocaleString() : 'Never'}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Created</p>
                        <p className="mt-0.5 text-xs text-zinc-300">
                          {new Date(active.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Status</p>
                        <span
                          data-testid={`key-status-${role}`}
                          className="mt-0.5 inline-block rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-400"
                        >
                          {active.status}
                        </span>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setRevokeError(null);
                        setRevokeTarget(active);
                      }}
                      data-testid={`revoke-key-${role}`}
                      className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 transition hover:bg-red-500/20"
                    >
                      Revoke
                    </button>
                  </div>
                ) : (
                  /* ── Empty state (never generated, or revoked — slot freed) ── */
                  <div
                    className="flex h-20 flex-col items-start justify-center gap-2"
                    data-testid={`key-empty-${role}`}
                  >
                    <p className="text-xs text-zinc-500">No active key for this slot.</p>
                    <button
                      type="button"
                      onClick={() => generate(role)}
                      data-testid={`generate-key-${role}`}
                      className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white shadow-md shadow-red-600/20 transition hover:bg-red-500"
                    >
                      Generate
                    </button>
                  </div>
                )}
              </div>
            </section>
          );
        })}
      </div>

      {/* ── Gateway reference row ───────────────────────────────────────── */}
      <GatewayRow
        gatewayUrl={gatewayUrl}
        curlExample={curlExample}
        copiedKey={copiedKey}
        copy={copy}
      />

      {/* ── Generate modal with plaintext-once panel ────────────────────── */}
      {generatingRole && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-red-400" />
              <h3 className="text-sm font-semibold text-zinc-100">
                Generate {generatingRole === 'master' ? 'master' : 'view-only'} key
              </h3>
            </div>

            {creating && (
              <div className="mt-6 flex items-center justify-center gap-2 text-xs text-zinc-400">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Generating…</span>
              </div>
            )}

            {generateError && (
              <p data-testid="generate-error" className="mt-4 text-xs text-red-400">
                {generateError}
              </p>
            )}

            {plaintext && (
              <div className="mt-4" data-testid="plaintext-panel">
                <p className="text-xs font-medium text-amber-400">
                  Save this key now — it will never be shown again.
                </p>
                <div className="mt-2 flex items-start justify-between gap-2 rounded-lg border border-zinc-700 bg-zinc-950 p-3">
                  <code className="min-w-0 flex-1 break-all font-mono text-xs text-zinc-200" data-testid="plaintext-value">
                    {plaintext}
                  </code>
                  <CopyButton copied={copiedKey === 'plaintext'} onClick={() => copy('plaintext', plaintext)} testid="plaintext-copy" />
                </div>
                <label className="mt-3 flex items-center gap-2 text-xs text-zinc-300">
                  <input
                    type="checkbox"
                    checked={savedConfirmed}
                    onChange={(e) => setSavedConfirmed(e.target.checked)}
                    data-testid="saved-checkbox"
                    className="h-3.5 w-3.5 accent-red-600"
                  />
                  <span>I have saved this key</span>
                </label>
                <button
                  type="button"
                  onClick={closeGenerateModal}
                  disabled={!savedConfirmed}
                  data-testid="plaintext-done-btn"
                  className="mt-4 w-full rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Done
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Revoke confirm modal ──────────────────────────────────────────── */}
      {revokeTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
            <h3 className="text-sm font-semibold text-zinc-100">
              Revoke {revokeTarget.role === 'master' ? 'master' : 'view-only'} key?
            </h3>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              Integrations using <span className="font-mono text-zinc-200">{revokeTarget.key_prefix}</span> will
              immediately lose gateway access. The slot is freed and a new key can be generated.
            </p>
            {revokeError && (
              <p data-testid="revoke-error" className="mt-2 text-xs text-red-400">
                {revokeError}
              </p>
            )}
            <div className="mt-5 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setRevokeTarget(null)}
                className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={confirmRevoke}
                disabled={revoking}
                data-testid="confirm-revoke-btn"
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-60"
              >
                {revoking && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                <span>Revoke</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/** K2: gateway URL + collapsible curl example (also shown to non-admins). */
function GatewayRow({
  gatewayUrl,
  curlExample,
  copiedKey,
  copy,
}: {
  gatewayUrl: string;
  curlExample: string;
  copiedKey: string | null;
  copy: (key: string, text: string) => void;
}) {
  const [curlOpen, setCurlOpen] = useState(false);
  return (
    <section className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5" data-testid="gateway-row">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">Project gateway</p>
          <p className="mt-0.5 truncate font-mono text-xs text-zinc-300" data-testid="gateway-url">
            {gatewayUrl}
          </p>
        </div>
        <CopyButton copied={copiedKey === 'gateway-url'} onClick={() => copy('gateway-url', gatewayUrl)} testid="gateway-copy" />
      </div>

      <button
        type="button"
        onClick={() => setCurlOpen((o) => !o)}
        data-testid="curl-toggle"
        className="mt-3 font-mono text-[11px] text-zinc-400 transition hover:text-red-400"
      >
        {curlOpen ? '▾ Hide curl example' : '▸ Show curl example'}
      </button>
      {curlOpen && (
        <div className="mt-2 rounded-lg border border-zinc-700 bg-zinc-950 p-3">
          <pre className="overflow-x-auto font-mono text-[11px] leading-relaxed text-zinc-300" data-testid="curl-example">
            {curlExample}
          </pre>
          <div className="mt-2 flex justify-end">
            <CopyButton
              copied={copiedKey === 'curl'}
              onClick={() => copy('curl', curlExample)}
              testid="curl-copy"
            />
          </div>
        </div>
      )}
    </section>
  );
}
