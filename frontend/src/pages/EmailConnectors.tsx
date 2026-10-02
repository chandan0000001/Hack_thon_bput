import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  AlertTriangle,
  CheckCircle2,
  Cloud,
  ExternalLink,
  FileSearch,
  FolderClock,
  Loader2,
  Mail,
  Pause,
  Play,
  PlugZap,
  RefreshCw,
  RotateCcw,
  Settings2,
  Trash2,
  Unplug,
  X,
  XCircle,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import VerboseResultPanel from '../components/common/VerboseResultPanel';
import EmailAnalysisResultCard from '../components/common/EmailAnalysisResultCard';
import * as api from '../services/api';
import { formatLocal } from '../utils/datetime';
import type {
  ConnectorSettings,
  EmailConnectorAccount,
  EmailProviderRegistryEntry,
  MessageAnalysis,
  ScanResult,
} from '../types';

const PROVIDER_ICONS: Record<string, typeof Mail> = {
  gmail: Mail,
  outlook: Mail,
  yahoo: Mail,
  icloud: Mail,
};

const STATUS_STYLES: Record<string, string> = {
  connected: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  paused: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/30',
  reauth_required: 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/30',
  revoked: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
  error: 'bg-red-500/10 text-red-400 ring-1 ring-red-500/30',
};

const PROVIDER_STATUS_STYLES: Record<string, string> = {
  enabled: 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30',
  coming_soon: 'bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700',
  unsupported: 'bg-zinc-900 text-zinc-600 ring-1 ring-zinc-800',
};

function formatWhen(iso: string | null): string {
  return formatLocal(iso);
}

function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return 'recently';
  const diffMs = Date.now() - new Date(iso).getTime();
  if (diffMs < 0) return 'just now';
  const diffSecs = Math.floor(diffMs / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

function formatCountdown(removesAtIso: string | null | undefined): string {
  if (!removesAtIso) return '3 days';
  const diffMs = new Date(removesAtIso).getTime() - Date.now();
  if (diffMs <= 0) return 'soon';
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  if (diffHours >= 48) {
    const days = Math.floor(diffHours / 24);
    const remHours = diffHours % 24;
    return `${days}d ${remHours}h`;
  }
  if (diffHours >= 1) {
    const mins = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
    return `${diffHours}h ${mins}m`;
  }
  const mins = Math.max(1, Math.floor(diffMs / (1000 * 60)));
  return `${mins}m`;
}

export default function EmailConnectors() {
  const [searchParams, setSearchParams] = useSearchParams();

  const [registry, setRegistry] = useState<EmailProviderRegistryEntry[]>([]);
  const [connectors, setConnectors] = useState<EmailConnectorAccount[]>([]);
  const [gmailAccounts, setGmailAccounts] = useState<api.GmailAccountItem[]>([]);
  const [recentAccounts, setRecentAccounts] = useState<api.GmailAccountItem[]>([]);
  const [accountToRemove, setAccountToRemove] = useState<api.GmailAccountItem | null>(null);
  const [connectorToDisconnect, setConnectorToDisconnect] = useState<EmailConnectorAccount | null>(null);
  const [removingId, setRemovingId] = useState<string | null>(null);
  const [reconnectingId, setReconnectingId] = useState<string | null>(null);
  const [pausingId, setPausingId] = useState<string | null>(null);
  const [resumingId, setResumingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [authorizing, setAuthorizing] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [disconnectingId, setDisconnectingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null);
  const [scanningConnector, setScanningConnector] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<ScanResult[] | null>(null);
  const [scannedConnector, setScannedConnector] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<MessageAnalysis | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [settingsFor, setSettingsFor] = useState<EmailConnectorAccount | null>(null);
  const [settings, setSettings] = useState<ConnectorSettings | null>(null);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [customHours, setCustomHours] = useState('');

  const oauthStatus = searchParams.get('status');
  const oauthReason = searchParams.get('reason');
  const oauthProvider = searchParams.get('connected');

  const [activity, setActivity] = useState<api.IngestionActivity | null>(null);
  const [activityLoading, setActivityLoading] = useState(false);
  const [autoRefreshActivity, setAutoRefreshActivity] = useState(true);

  const loadActivity = useCallback(async () => {
    try {
      const data = await api.getIngestionActivity();
      setActivity(data);
    } catch {
      // silent fallback
    }
  }, []);

  useEffect(() => {
    loadActivity();
    if (!autoRefreshActivity) return;
    const interval = setInterval(loadActivity, 4000);
    return () => clearInterval(interval);
  }, [loadActivity, autoRefreshActivity]);

  const load = useCallback(async () => {
    setLoading(true);
    setActionError(null);
    try {
      const [caps, conns, gmailData] = await Promise.all([
        api.listConnectorCapabilities(),
        api.listEmailConnectors(),
        api.listGmailAccounts().catch(() => ({ connected: [], recent: [] })),
      ]);
      setRegistry(caps);
      // Connected Accounts section renders active connected and paused rows
      setConnectors(conns.filter((c) => c.status === 'connected' || c.status === 'paused'));
      setGmailAccounts(gmailData.connected || []);
      setRecentAccounts(gmailData.recent || []);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to load connectors');
    } finally {
      setLoading(false);
    }
  }, []);

  const getGmailAccount = (connector: EmailConnectorAccount): api.GmailAccountItem | undefined => {
    return gmailAccounts.find(
      (a) => a.email.toLowerCase() === connector.provider_email.toLowerCase()
    );
  };

  const isConnectorPaused = (connector: EmailConnectorAccount): boolean => {
    if (connector.status === 'paused') return true;
    const gAcc = getGmailAccount(connector);
    return gAcc?.status === 'paused' || gAcc?.sync_status === 'paused';
  };

  const handlePause = async (connector: EmailConnectorAccount) => {
    setPausingId(connector.id);
    setActionError(null);
    try {
      const gAcc = getGmailAccount(connector);
      await api.pauseGmailAccount(gAcc?.id);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to pause Gmail sync');
    } finally {
      setPausingId(null);
    }
  };

  const handleResume = async (connector: EmailConnectorAccount) => {
    setResumingId(connector.id);
    setActionError(null);
    try {
      const gAcc = getGmailAccount(connector);
      await api.resumeGmailAccount(gAcc?.id);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to resume Gmail sync');
    } finally {
      setResumingId(null);
    }
  };

  const handleConfirmDisconnect = async () => {
    if (!connectorToDisconnect) return;
    setDisconnectingId(connectorToDisconnect.id);
    setActionError(null);
    setTestResult(null);
    try {
      await api.disconnectEmailConnector(connectorToDisconnect.id);
      setConnectorToDisconnect(null);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to disconnect');
    } finally {
      setDisconnectingId(null);
    }
  };

  const handleReconnect = async (account: api.GmailAccountItem) => {
    setReconnectingId(account.id);
    setActionError(null);
    try {
      const url = await api.authorizeGmailConnector(undefined, account.id);
      window.location.href = url;
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to reconnect Gmail');
      setReconnectingId(null);
    }
  };

  const handleConfirmRemove = async () => {
    if (!accountToRemove) return;
    setRemovingId(accountToRemove.id);
    setActionError(null);
    try {
      await api.earlyRemoveGmailAccount(accountToRemove.id);
      setAccountToRemove(null);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to remove account');
    } finally {
      setRemovingId(null);
    }
  };

  useEffect(() => {
    load();
  }, [load]);

  // Clear the OAuth banner params once dismissed (any interaction).
  const dismissBanner = useCallback(() => {
    if (searchParams.get('connected')) {
      searchParams.delete('connected');
      searchParams.delete('status');
      searchParams.delete('reason');
      setSearchParams(searchParams, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const handleConnectGmail = async () => {
    setAuthorizing(true);
    setActionError(null);
    try {
      const url = await api.authorizeGmailConnector();
      window.location.href = url; // navigate to the Google consent screen
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to start Gmail authorization');
      setAuthorizing(false);
    }
  };

  const handleTest = async (connector: EmailConnectorAccount) => {
    setTestingId(connector.id);
    setTestResult(null);
    setActionError(null);
    try {
      const result = await api.testEmailConnector(connector.id);
      const email = (result as { email_address?: string }).email_address;
      setTestResult({
        id: connector.id,
        ok: result.ok,
        message: result.ok
          ? email
            ? `Connection OK for ${email}`
            : 'Connection OK'
          : result.message ?? 'Connection test failed',
      });
      await load();
    } catch (err) {
      setTestResult({
        id: connector.id,
        ok: false,
        message: err instanceof Error ? err.message : 'Connection test failed',
      });
    } finally {
      setTestingId(null);
    }
  };

  const handleScan = async (connector: EmailConnectorAccount) => {
    setScanningConnector(connector.id);
    setActionError(null);
    setScanResults(null);
    setScannedConnector(null);
    try {
      const results = await api.scanConnectorMessages(connector.id, { scan_recent: 10 });
      setScanResults(results);
      setScannedConnector(connector.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Mailbox scan failed');
    } finally {
      setScanningConnector(null);
    }
  };

  const openAnalysis = async (connectorId: string, messageId: string) => {
    setAnalysisLoading(true);
    setAnalysis(null);
    try {
      setAnalysis(await api.getMessageAnalysis(connectorId, messageId));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to load analysis');
    } finally {
      setAnalysisLoading(false);
    }
  };

  const openSettings = async (connector: EmailConnectorAccount) => {
    setSettingsFor(connector);
    setActionError(null);
    try {
      const current = await api.getConnectorSettings(connector.id);
      setSettings(current);
      setCustomHours(current.quarantine_expiry_hours ? String(current.quarantine_expiry_hours) : '');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to load settings');
    }
  };

  const saveSettings = async (patch: Parameters<typeof api.updateConnectorSettings>[1]) => {
    if (!settingsFor) return;
    setSettingsSaving(true);
    setActionError(null);
    try {
      const updated = await api.updateConnectorSettings(settingsFor.id, patch);
      setSettings(updated);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSettingsSaving(false);
    }
  };

  const gmailEntry = registry.find((r) => r.provider === 'gmail');
  const otherProviders = registry.filter((r) => r.provider !== 'gmail');
  const gmailEnabled = gmailEntry?.status === 'enabled';

  return (
    <div className="space-y-6" onClick={() => oauthStatus && dismissBanner()}>
      <PageHeader
        title="Email Connectors"
        description="Connect your mailbox so CYBERGUARD can scan authorized messages and perform real provider-backed actions."
      />

      {/* OAuth result banner */}
      {oauthProvider && (
        <div
          className={`flex items-start gap-2 rounded-lg border p-3.5 text-sm ${
            oauthStatus === 'success'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
              : 'border-red-500/40 bg-red-500/10 text-red-300'
          }`}
        >
          {oauthStatus === 'success' ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" />
          ) : (
            <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" />
          )}
          <div>
            <p className="font-semibold">
              {oauthStatus === 'success'
                ? `${oauthProvider === 'gmail' ? 'Gmail' : oauthProvider} connected successfully`
                : `${oauthProvider === 'gmail' ? 'Gmail' : oauthProvider} connection failed`}
            </p>
            {oauthStatus !== 'success' && (
              <p className="mt-0.5 text-xs opacity-80">
                Reason: {oauthReason ?? 'unknown'} — check the operation log below or try connecting again.
              </p>
            )}
          </div>
        </div>
      )}

      {actionError && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          {actionError}
        </div>
      )}

      {/* Provider cards */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {[gmailEntry, ...otherProviders].filter(Boolean).map((entry) => {
          const Icon = PROVIDER_ICONS[entry!.provider] ?? Cloud;
          const isGmail = entry!.provider === 'gmail';
          return (
            <div
              key={entry!.provider}
              className="flex flex-col rounded-2xl border border-zinc-800 bg-zinc-900/90 p-5 shadow-sm backdrop-blur"
            >
              <div className="flex items-center justify-between">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-zinc-950 ring-1 ring-zinc-800">
                  <Icon className="h-5 w-5 text-zinc-300" />
                </div>
                <span
                  className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                    PROVIDER_STATUS_STYLES[entry!.status] ?? PROVIDER_STATUS_STYLES.coming_soon
                  }`}
                >
                  {entry!.status.replace('_', ' ')}
                </span>
              </div>
              <h3 className="mt-3 text-sm font-semibold text-zinc-100">{entry!.display_name}</h3>
              <p className="mt-1 flex-1 text-xs leading-relaxed text-zinc-500">
                {entry!.detail || (entry!.status === 'enabled' ? 'Ready to connect with mailbox modify access.' : '')}
              </p>
              {isGmail && (
                <button
                  type="button"
                  onClick={handleConnectGmail}
                  disabled={authorizing || !gmailEnabled}
                  className="mt-4 flex items-center justify-center gap-2 rounded-lg bg-red-600 py-2 text-xs font-bold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-50"
                  title={gmailEnabled ? 'Connect your Gmail mailbox' : entry!.detail || 'Gmail connector is not configured yet'}
                >
                  {authorizing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlugZap className="h-3.5 w-3.5" />}
                  Connect Gmail
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Connected accounts */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-zinc-100">Connected Accounts</h2>
          <button
            type="button"
            onClick={load}
            className="flex items-center gap-1.5 text-xs text-zinc-400 transition hover:text-red-400"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading connectors…
          </div>
        ) : connectors.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">
            No mailboxes connected yet. {gmailEnabled ? 'Connect Gmail above to get started.' : 'Gmail needs backend configuration (Google OAuth client + CONNECTOR_TOKEN_KEY) before it can be connected.'}
          </div>
        ) : (
          <div className="divide-y divide-zinc-800">
            {connectors.map((connector) => {
              const paused = isConnectorPaused(connector);
              return (
                <div key={connector.id} className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-zinc-100">{connector.provider_email}</span>
                      <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400">
                        {connector.provider}
                      </span>
                      <span className={`rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${STATUS_STYLES[paused ? 'paused' : 'connected']}`}>
                        {paused ? 'PAUSED' : 'CONNECTED'}
                      </span>
                    </div>
                    <p className="mt-1 truncate font-mono text-[11px] text-zinc-500">
                      Scopes: {connector.scopes.length ? connector.scopes.join(', ') : '—'} · Last test: {formatWhen(connector.last_test_at)}
                    </p>
                    {connector.last_error && (
                      <p className="mt-1 text-xs text-red-400">{connector.last_error}</p>
                    )}
                    {testResult?.id === connector.id && (
                      <p className={`mt-1 text-xs ${testResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                        {testResult.ok ? '✔ ' : '✖ '}
                        {testResult.message}
                      </p>
                    )}
                  </div>
                  <div className="flex flex-shrink-0 items-center gap-2">
                    {connector.provider === 'gmail' && (
                      paused ? (
                        <button
                          type="button"
                          onClick={() => handleResume(connector)}
                          disabled={resumingId === connector.id}
                          className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                        >
                          {resumingId === connector.id ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Play className="h-3.5 w-3.5" />
                          )}
                          Resume Sync
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handlePause(connector)}
                          disabled={pausingId === connector.id}
                          className="flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-400 transition hover:bg-amber-500/20 disabled:opacity-50"
                        >
                          {pausingId === connector.id ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Pause className="h-3.5 w-3.5" />
                          )}
                          Pause Sync
                        </button>
                      )
                    )}
                    {connector.provider === 'gmail' && !paused && (
                      <button
                        type="button"
                        onClick={() => handleScan(connector)}
                        disabled={scanningConnector === connector.id}
                        className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:border-red-500/40 hover:bg-zinc-800/60 disabled:opacity-50"
                      >
                        {scanningConnector === connector.id ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <FileSearch className="h-3.5 w-3.5" />
                        )}
                        {scanningConnector === connector.id ? 'Scanning…' : 'Scan Recent Mail'}
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => openSettings(connector)}
                      className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:border-zinc-700 hover:bg-zinc-800/60"
                    >
                      <Settings2 className="h-3.5 w-3.5" />
                      Settings
                    </button>
                    <button
                      type="button"
                      onClick={() => handleTest(connector)}
                      disabled={testingId === connector.id}
                      className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:border-zinc-700 hover:bg-zinc-800/60 disabled:opacity-50"
                    >
                      {testingId === connector.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ExternalLink className="h-3.5 w-3.5" />}
                      Test
                    </button>
                    <button
                      type="button"
                      onClick={() => setConnectorToDisconnect(connector)}
                      disabled={disconnectingId === connector.id}
                      className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
                    >
                      {disconnectingId === connector.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unplug className="h-3.5 w-3.5" />}
                      Disconnect
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Recently Connected */}
      {recentAccounts.length > 0 && (
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
          <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
            <div className="flex items-center gap-2">
              <FolderClock className="h-4 w-4 text-zinc-400" />
              <h2 className="text-sm font-semibold text-zinc-100">Recently Connected</h2>
              <span className="rounded-full bg-zinc-800 px-2 py-0.5 font-mono text-[10px] text-zinc-400">
                {recentAccounts.length}
              </span>
            </div>
          </div>
          <div className="divide-y divide-zinc-800">
            {recentAccounts.map((account) => (
              <div key={account.id} className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-zinc-300">{account.email}</span>
                    <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400">
                      gmail
                    </span>
                    <span className="rounded px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider bg-zinc-800 text-zinc-400 ring-1 ring-zinc-700">
                      DISCONNECTED
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-zinc-500">
                    Disconnected {formatRelativeTime(account.disconnected_at)} — credentials removed. Auto-removes in {formatCountdown(account.removes_at)}.
                  </p>
                </div>
                <div className="flex flex-shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleReconnect(account)}
                    disabled={reconnectingId === account.id}
                    className="flex items-center gap-1.5 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-bold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500 disabled:opacity-50"
                  >
                    {reconnectingId === account.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
                    Reconnect
                  </button>
                  <button
                    type="button"
                    onClick={() => setAccountToRemove(account)}
                    disabled={removingId === account.id}
                    className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-1.5 text-xs font-semibold text-zinc-400 transition hover:border-red-500/40 hover:text-red-400 disabled:opacity-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Remove now
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Real-time Mailbox Ingestion & Threat Analysis Monitor */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
        <div className="flex flex-col gap-3 border-b border-zinc-800 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <span className="relative flex h-3 w-3">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-500"></span>
            </span>
            <div>
              <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                Live Ingestion & Threat Analysis Monitor
              </h2>
              <p className="text-xs text-zinc-400">
                Listening for real-time mailbox push notifications via Google Cloud Pub/Sub & background worker pipeline.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setAutoRefreshActivity(!autoRefreshActivity)}
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                autoRefreshActivity
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                  : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <span className={`inline-block h-2 w-2 rounded-full ${autoRefreshActivity ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
              Auto-refresh (4s)
            </button>
            <button
              type="button"
              onClick={async () => {
                setActivityLoading(true);
                await loadActivity();
                setActivityLoading(false);
              }}
              disabled={activityLoading}
              className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-xs font-medium text-zinc-300 transition hover:border-zinc-700 hover:bg-zinc-800/60 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${activityLoading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* Metric summary bar */}
        {activity && (
          <div className="grid grid-cols-3 divide-x divide-zinc-800 border-b border-zinc-800 bg-zinc-950/40 text-center text-xs">
            <div className="py-2.5">
              <span className="text-zinc-500">Processed Emails: </span>
              <span className="font-semibold text-zinc-200">{activity.summary.total_processed}</span>
            </div>
            <div className="py-2.5">
              <span className="text-zinc-500">Threats Detected: </span>
              <span className="font-semibold text-red-400">{activity.summary.threats_detected}</span>
            </div>
            <div className="py-2.5">
              <span className="text-zinc-500">Auto-Quarantined: </span>
              <span className="font-semibold text-orange-400">{activity.summary.quarantined}</span>
            </div>
          </div>
        )}

        {/* Email processing log table */}
        {!activity || activity.recent_emails.length === 0 ? (
          <div className="px-5 py-8 text-center text-sm text-zinc-500">
            {activityLoading ? (
              <div className="flex items-center justify-center gap-2 text-zinc-400">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading recent activity...
              </div>
            ) : (
              'No mailbox events processed yet. Send a test email to your connected Gmail to observe real-time ingestion, analysis, and action.'
            )}
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/80 overflow-x-auto">
            {activity.recent_emails.map((email) => {
              const severity =
                email.severity ||
                (email.classification === 'phishing' || (email.risk_score ?? 0) >= 0.7
                  ? 'critical'
                  : email.classification === 'suspicious'
                    ? 'medium'
                    : 'safe');
              return (
                <EmailAnalysisResultCard
                  key={email.id}
                  severity={severity}
                  subject={email.subject || '(No Subject)'}
                  sender={email.sender || 'Unknown'}
                  receivedAt={email.received_at || email.created_at}
                  score={email.risk_score}
                  engines={email.engines}
                  recommendedAction={email.recommended_action}
                  providerOperationStatus={email.provider_operation_status}
                  processingStatus={email.processing_status}
                  enforcementDetail={email.enforcement_detail}
                />
              );
            })}
          </div>
        )}
      </div>

      {/* Scan results */}
      {scanResults !== null && scannedConnector && (
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-sm backdrop-blur">
          <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
            <h2 className="text-sm font-semibold text-zinc-100">
              Scan Results{' '}
              <span className="font-mono text-xs text-zinc-500">
                ({scanResults.length} message{scanResults.length === 1 ? '' : 's'} analyzed · analysis only, no mailbox actions performed)
              </span>
            </h2>
            <button
              type="button"
              onClick={() => { setScanResults(null); setScannedConnector(null); }}
              className="text-xs text-zinc-400 transition hover:text-red-400"
            >
              Clear
            </button>
          </div>

          {scanResults.length === 0 ? (
            <div className="px-5 py-10 text-center text-sm text-zinc-500">
              The mailbox returned no messages to scan.
            </div>
          ) : (
            <div className="divide-y divide-zinc-800">
              {[...scanResults]
                .sort((a, b) => b.overall_score - a.overall_score)
                .map((result) => (
                  <EmailAnalysisResultCard
                    key={result.message_id}
                    severity={result.overall_severity}
                    subject={result.subject || '(no subject)'}
                    sender={result.sender}
                    score={result.overall_score}
                    engines={result.feature_analyses.map((f) => ({ engine: f.engine, score: f.score }))}
                    recommendedAction={result.recommended_action}
                    providerOperationStatus={result.provider_operation_status}
                    onClick={() => openAnalysis(scannedConnector, result.message_id)}
                  />
                ))}
            </div>
          )}
        </div>
      )}

      {/* Analysis drawer */}
      {analysisLoading && (
        <div className="flex items-center justify-center gap-2 rounded-2xl border border-zinc-800 bg-zinc-900/90 px-5 py-10 text-sm text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading full analysis…
        </div>
      )}
      {analysis && (
        <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/70 backdrop-blur-sm" onClick={() => setAnalysis(null)}>
          <div
            className="h-full w-full max-w-3xl overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-zinc-100">{analysis.scan.subject || '(no subject)'}</h3>
                <p className="mt-0.5 font-mono text-xs text-zinc-500">
                  {analysis.scan.sender} · {analysis.message.recipients.join(', ') || '—'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setAnalysis(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 text-zinc-400 transition hover:text-red-400"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <VerboseResultPanel scan={analysis.scan} />

            <div className="mt-5">
              <h4 className="mb-2 font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">
                Message body
              </h4>
              {analysis.message.body_html ? (
                <iframe
                  title="message-body"
                  sandbox=""
                  srcDoc={analysis.message.body_html}
                  className="h-96 w-full rounded-xl border border-zinc-800 bg-white"
                />
              ) : (
                <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-zinc-800 bg-zinc-900/90 p-4 text-xs leading-relaxed text-zinc-300">
                  {analysis.message.body_text || '(empty body)'}
                </pre>
              )}
              {analysis.message.attachments_meta.length > 0 && (
                <p className="mt-2 font-mono text-[11px] text-zinc-500">
                  Attachments (metadata only):{' '}
                  {analysis.message.attachments_meta.map((a) => `${a.filename} (${a.mime_type})`).join(', ')}
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Connector enforcement settings drawer */}
      {settingsFor && settings && (
        <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/70 backdrop-blur-sm" onClick={() => setSettingsFor(null)}>
          <div
            className="h-full w-full max-w-md overflow-y-auto border-l border-zinc-800 bg-zinc-950 p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-zinc-100">Enforcement Settings</h3>
                <p className="mt-0.5 font-mono text-xs text-zinc-500">{settingsFor.provider_email}</p>
              </div>
              <button
                type="button"
                onClick={() => setSettingsFor(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 text-zinc-400 transition hover:text-red-400"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-5">
              <div>
                <label className="mb-1.5 block font-mono text-[11px] font-bold uppercase tracking-wider text-zinc-400">
                  Quarantine expiry
                </label>
                <select
                  value={
                    settings.quarantine_expiry_hours === null
                      ? 'manual'
                      : [3, 24].includes(settings.quarantine_expiry_hours)
                        ? String(settings.quarantine_expiry_hours)
                        : 'custom'
                  }
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v === 'manual') saveSettings({ expiry_mode: 'manual' });
                    else if (v === '3') saveSettings({ expiry_mode: 'hours', quarantine_expiry_hours: 3 });
                    else if (v === '24') saveSettings({ expiry_mode: 'hours', quarantine_expiry_hours: 24 });
                    else if (v === 'custom') saveSettings({ expiry_mode: 'hours', quarantine_expiry_hours: 72 });
                  }}
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2.5 text-sm text-zinc-100 outline-none focus:border-red-500/60"
                >
                  <option value="3">3 Hours</option>
                  <option value="24">24 Hours</option>
                  <option value="custom">Custom</option>
                  <option value="manual">Manual (Never expire)</option>
                </select>
                {settings.quarantine_expiry_hours !== null &&
                  ![3, 24].includes(settings.quarantine_expiry_hours) && (
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        type="number"
                        min={1}
                        max={720}
                        value={customHours}
                        onChange={(e) => setCustomHours(e.target.value)}
                        className="w-24 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-red-500/60"
                      />
                      <span className="text-xs text-zinc-400">hours</span>
                      <button
                        type="button"
                        disabled={settingsSaving || !customHours}
                        onClick={() => saveSettings({ expiry_mode: 'hours', quarantine_expiry_hours: Number(customHours) })}
                        className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-50"
                      >
                        Apply
                      </button>
                    </div>
                  )}
              </div>

              <label className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900/90 p-4">
                <div>
                  <p className="text-sm font-semibold text-zinc-100">Auto-quarantine</p>
                  <p className="mt-0.5 text-xs text-zinc-500">Enforce quarantine and sender blocks automatically on high/critical verdicts.</p>
                </div>
                <input
                  type="checkbox"
                  checked={settings.auto_quarantine_enabled}
                  disabled={settingsSaving}
                  onChange={(e) => saveSettings({ auto_quarantine_enabled: e.target.checked })}
                  className="h-5 w-5 accent-red-600"
                />
              </label>

              <label className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900/90 p-4">
                <div>
                  <p className="text-sm font-semibold text-zinc-100">Permanent delete</p>
                  <p className="mt-0.5 text-xs text-zinc-500">
                    OFF: deletion moves mail to Gmail trash. ON: deletion permanently removes mail from Gmail.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={settings.permanent_delete_enabled}
                  disabled={settingsSaving}
                  onChange={(e) => saveSettings({ permanent_delete_enabled: e.target.checked })}
                  className="h-5 w-5 accent-red-600"
                />
              </label>

              {settingsSaving && (
                <p className="flex items-center gap-2 text-xs text-zinc-500">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Saving…
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Remove Confirmation Modal */}
      {accountToRemove && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div
            className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10 text-red-400">
                  <AlertTriangle className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-zinc-100">Remove from recently connected?</h3>
                  <p className="font-mono text-xs text-zinc-400">{accountToRemove.email}</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setAccountToRemove(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 text-zinc-400 transition hover:text-red-400"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <p className="text-sm text-zinc-400">
              Remove from recently connected? Scan history will be preserved.
            </p>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setAccountToRemove(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmRemove}
                disabled={removingId === accountToRemove.id}
                className="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-50"
              >
                {removingId === accountToRemove.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                Remove now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Disconnect Confirmation Modal */}
      {connectorToDisconnect && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div
            className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10 text-red-400">
                  <AlertTriangle className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-zinc-100">Disconnect Mailbox</h3>
                  <p className="font-mono text-xs text-zinc-400">{connectorToDisconnect.provider_email}</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setConnectorToDisconnect(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 p-1.5 text-zinc-400 transition hover:text-red-400"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <p className="text-sm text-zinc-300 leading-relaxed">
              Stops mailbox monitoring, revokes Google authorization, and removes stored credentials and watch state. Recent entry kept 3 days for reconnect. Scan history is retained for audit.
            </p>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setConnectorToDisconnect(null)}
                className="rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-2 text-xs font-semibold text-zinc-300 transition hover:bg-zinc-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDisconnect}
                disabled={disconnectingId === connectorToDisconnect.id}
                className="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-bold text-white transition hover:bg-red-500 disabled:opacity-50"
              >
                {disconnectingId === connectorToDisconnect.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unplug className="h-3.5 w-3.5" />}
                Disconnect
              </button>
            </div>
          </div>
        </div>
      )}

      <p className="text-[11px] leading-relaxed text-zinc-600">
        Gmail access uses CYBERGUARD's own Google OAuth client with the
        gmail.modify scope. Tokens are encrypted at rest on the server and are
        never sent to the browser. Phase 3 adds mailbox scanning; quarantine and
        sender actions follow in Phase 4.
      </p>
    </div>
  );
}
