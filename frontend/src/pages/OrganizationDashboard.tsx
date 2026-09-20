import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ArrowRight,
  Ban,
  BellRing,
  Inbox,
  Mail,
  Network,
  RefreshCw,
  ScrollText,
  Settings,
  ShieldAlert,
  Terminal,
  UserX,
  Video,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useUiStore } from '../store/uiStore';
import { useOrgRealtime } from '../hooks/useOrgRealtime';
import * as orgApi from '../services/orgApi';

const MODULES = [
  {
    to: 'phishing',
    label: 'Phishing',
    description: 'Org-scoped phishing verdicts with verbose indicators.',
    icon: Mail,
    enabled: true,
  },
  {
    to: 'url',
    label: 'URL',
    description: 'Reputation-aware malicious URL analysis for org traffic.',
    icon: Network,
    enabled: true,
  },
  {
    to: 'deepfake',
    label: 'Deepfake',
    description: 'Media forensics and synthetic-media detection.',
    icon: Video,
    enabled: true,
  },
  {
    to: 'impersonation',
    label: 'Impersonation',
    description: 'Brand / executive impersonation and BEC detection.',
    icon: UserX,
    enabled: true,
  },
  {
    to: '../logs',
    label: 'Live Log Analysis',
    description: 'Splunk-style stream of gateway-ingested logs, auto-analyzed.',
    icon: Terminal,
    enabled: true,
  },
  {
    to: '../mail-servers',
    label: 'Mail Servers',
    description: 'Server-to-server connectors (Workspace, M365, IMAP) with per-server settings and logs.',
    icon: Mail,
    enabled: true,
  },
  {
    to: '../notifications',
    label: 'Email Groups',
    description: 'Role-grouped notification lists and per-event-type email routing.',
    icon: BellRing,
    enabled: true,
  },
];

const SUMMARY_CARDS = [
  { key: 'total_scans', label: 'Total Scans', icon: Inbox },
  { key: 'threats_detected', label: 'Threats Detected', icon: ShieldAlert },
  { key: 'quarantined_emails', label: 'Quarantined Emails', icon: Mail },
  { key: 'blocked_senders', label: 'Blocked Senders', icon: Ban },
  { key: 'critical_alerts', label: 'Critical Alerts', icon: BellRing },
] as const;

/**
 * ORG-2: main organization dashboard — headline metrics + module grid.
 * Real-time: summary and feeds refresh on Supabase postgres_changes for the
 * org (alerts / org_log_events); a light 15 s fallback covers demo setups
 * without realtime.
 */
export default function OrganizationDashboard() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const [summary, setSummary] = useState<orgApi.DashboardSummary | null>(null);
  const [live, setLive] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    try {
      setSummary(await orgApi.getDashboardSummary(orgId));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load dashboard summary', 'high');
    }
  }, [orgId, addToast]);

  useEffect(() => {
    load();
  }, [load]);

  useOrgRealtime('alerts', orgId, () => {
    setLive(true);
    load();
  });

  useEffect(() => {
    if (!orgId) return;
    const t = setInterval(load, 15000); // fallback when realtime is unavailable
    return () => clearInterval(t);
  }, [orgId, load]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Organization Dashboard"
          description="Org-scoped threat posture, fed by gateway payloads and mail-server streams — no manual paste-boxes."
        />
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[10px] uppercase ring-1 ${
              live ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30' : 'bg-zinc-800 text-zinc-400 ring-zinc-600/40'
            }`}
          >
            {live ? 'Live' : 'Polling'}
          </span>
          <button
            onClick={load}
            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
          {orgId && (
            <Link
              to={`/org/${orgId}/settings`}
              className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3.5 py-2 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500"
            >
              <Settings className="h-4 w-4" />
              <span>Org Settings</span>
            </Link>
          )}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        {SUMMARY_CARDS.map((c) => {
          const Icon = c.icon;
          const value = summary ? summary[c.key] : null;
          const critical = c.key === 'critical_alerts' && (value ?? 0) > 0;
          return (
            <div key={c.key} className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-4 backdrop-blur">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">{c.label}</span>
                <Icon className={`h-4 w-4 ${critical ? 'text-red-400' : 'text-zinc-600'}`} />
              </div>
              <div className={`mt-2 text-2xl font-bold ${critical ? 'text-red-400' : 'text-zinc-100'}`}>
                {value ?? '…'}
              </div>
            </div>
          );
        })}
      </div>
      {summary?.last_scan_at && (
        <p className="-mt-3 font-mono text-[11px] text-zinc-500">
          Last scan: {new Date(summary.last_scan_at).toLocaleString()}
        </p>
      )}

      {/* Module grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {MODULES.map((m) => {
          const Icon = m.icon;
          const inner = (
            <>
              <div className="flex items-center justify-between">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 ring-1 ring-red-500/30">
                  <Icon className={`h-5 w-5 ${m.enabled ? 'text-red-400' : 'text-zinc-600'}`} />
                </div>
                {m.enabled ? (
                  <ArrowRight className="h-4 w-4 text-zinc-600 transition group-hover:translate-x-0.5 group-hover:text-zinc-300" />
                ) : (
                  <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-[10px] uppercase text-zinc-500">
                    Coming Soon
                  </span>
                )}
              </div>
              <h3 className={`mt-3 text-sm font-bold ${m.enabled ? 'text-zinc-100' : 'text-zinc-500'}`}>
                {m.label}
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-zinc-500">{m.description}</p>
            </>
          );
          return m.enabled ? (
            <Link
              key={m.label}
              to={m.to}
              className="group rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur transition hover:border-zinc-600"
            >
              {inner}
            </Link>
          ) : (
            <div
              key={m.label}
              aria-disabled
              className="cursor-not-allowed rounded-xl border border-zinc-800/60 bg-zinc-900/50 p-5 opacity-70"
            >
              {inner}
            </div>
          );
        })}
      </div>

      {/* Gateway note */}
      <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3.5 text-xs leading-relaxed text-amber-300">
        <ScrollText className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          <strong>Feeding this dashboard:</strong> scans arrive via the org gateway
          (<code className="font-mono">POST /api/v1/org/{orgId ?? '{org_id}'}/gateway</code>) and ingested logs via{' '}
          <code className="font-mono">/logs/ingest</code>. Create API keys under Org Settings. Mail-server
          connectors ship with ORG-3.
        </span>
      </div>
    </div>
  );
}
