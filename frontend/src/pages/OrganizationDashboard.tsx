import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  ArrowRight,
  Ban,
  BellRing,
  FolderOpen,
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
import OrgIngestionStrip from '../components/org/OrgIngestionStrip';
import { useUiStore } from '../store/uiStore';
import { useAuthStore } from '../store/authStore';
import { useOrgRealtime } from '../hooks/useOrgRealtime';
import * as orgApi from '../services/orgApi';

type TileDef = {
  key: string;
  label: string;
  description: string;
  icon: typeof Mail;
  to: string;
  /** event features show a severity bar; inventory features don't */
  kind: 'events' | 'inventory';
};

const TILES: TileDef[] = [
  {
    key: 'phishing',
    label: 'Phishing',
    description: 'Aggregated phishing verdict counts and severity mix for the selected project.',
    icon: Mail,
    to: 'phishing',
    kind: 'events',
  },
  {
    key: 'url',
    label: 'URL',
    description: 'Malicious URL detections — 7-day counts and severity mix.',
    icon: Network,
    to: 'url',
    kind: 'events',
  },
  {
    key: 'deepfake',
    label: 'Deepfake',
    description: 'Media forensics detections — 7-day counts and severity mix.',
    icon: Video,
    to: 'deepfake',
    kind: 'events',
  },
  {
    key: 'impersonation',
    label: 'Impersonation',
    description: 'Brand / executive impersonation detections — 7-day counts and severity mix.',
    icon: UserX,
    to: 'impersonation',
    kind: 'events',
  },
  {
    key: 'logs',
    label: 'Live Log Analysis',
    description: 'Gateway-ingested log events, auto-analyzed — 7-day counts and severity mix.',
    icon: Terminal,
    to: '../logs',
    kind: 'events',
  },
  {
    key: 'mail_servers',
    label: 'Mail Servers',
    description: 'Connected server-to-server connectors, by status.',
    icon: Mail,
    to: '../mail-servers',
    kind: 'inventory',
  },
  {
    key: 'email_groups',
    label: 'Email Groups',
    description: 'Registered notification recipients across all role groups.',
    icon: BellRing,
    to: '../notifications',
    kind: 'inventory',
  },
];

const SUMMARY_CARDS = [
  { key: 'total_scans', label: 'Total Scans', icon: Inbox },
  { key: 'threats_detected', label: 'Threats Detected', icon: ShieldAlert },
  { key: 'quarantined_emails', label: 'Quarantined Emails', icon: Mail },
  { key: 'blocked_senders', label: 'Blocked Senders', icon: Ban },
  { key: 'critical_alerts', label: 'Critical Alerts', icon: BellRing },
] as const;

const SEV_BAR_STYLES: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-500',
  low: 'bg-zinc-500',
  other: 'bg-zinc-600',
};

/** Stacked severity distribution bar (critical → low). */
function SeverityBar({ dist }: { dist: Record<string, number> }) {
  const order = ['critical', 'high', 'medium', 'low', 'other'];
  const total = order.reduce((sum, k) => sum + (dist[k] ?? 0), 0);
  if (total === 0) {
    return <div className="mt-3 h-1.5 w-full rounded-full bg-zinc-800" title="No events in the last 7 days" />;
  }
  return (
    <div className="mt-3 flex h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
      {order.map((sev) => {
        const count = dist[sev] ?? 0;
        if (!count) return null;
        return (
          <div
            key={sev}
            className={SEV_BAR_STYLES[sev]}
            style={{ width: `${(count / total) * 100}%` }}
            title={`${sev}: ${count}`}
          />
        );
      })}
    </div>
  );
}

/**
 * ORG-REDESIGN: main organization dashboard — headline metrics + AGGREGATED
 * per-feature tiles (count badge + severity distribution), scoped to the
 * project selected in the Topbar switcher. Tiles navigate to the aggregated
 * views; there are no per-user entry forms here.
 */
export default function OrganizationDashboard() {
  const { orgId } = useParams<{ orgId: string }>();
  const addToast = useUiStore((s) => s.addToast);
  const activeProject = useAuthStore((s) => s.activeProject);
  const activeProjectId = useAuthStore((s) => s.activeProjectId);
  const [summary, setSummary] = useState<orgApi.DashboardSummary | null>(null);
  const [live, setLive] = useState(false);

  const load = useCallback(async () => {
    if (!orgId) return;
    try {
      setSummary(await orgApi.getDashboardSummary(orgId, activeProjectId));
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to load dashboard summary', 'high');
    }
  }, [orgId, activeProjectId, addToast]);

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

  const features = summary?.features ?? {};

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Organization Dashboard"
          description={
            activeProject
              ? `Events for project: ${activeProject.name} — aggregated counts and severity distributions (last 7 days).`
              : 'Org-wide aggregated threat posture, fed by gateway payloads and mail-server streams. Select a project to scope the tiles.'
          }
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
          {activeProject ? (
            <button
              onClick={() => useAuthStore.getState().switchProject(null)}
              className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-200 transition hover:border-zinc-500"
              title="Show all projects (org-wide)"
            >
              <FolderOpen className="h-4 w-4" />
              All Projects
            </button>
          ) : null}
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

      {/* Ingestion health strip (ORG-LIVE-VIEWS) */}
      <OrgIngestionStrip orgId={orgId ?? ''} projectId={activeProjectId} />

      {/* Project scope banner */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/70 px-4 py-2.5 text-xs">
        <FolderOpen className="h-3.5 w-3.5 text-red-400" />
        {activeProject ? (
          <span className="text-zinc-300">
            Events for project: <span className="font-semibold text-zinc-100">{activeProject.name}</span>
            <span className="ml-2 font-mono text-[10px] text-zinc-500">{activeProject.slug}</span>
          </span>
        ) : (
          <span className="text-zinc-400">
            Showing all projects (org-wide). Pick one in the Topbar switcher to scope these tiles.
          </span>
        )}
        <Link
          to={orgId ? `/org/${orgId}/settings` : '#'}
          className="ml-auto text-red-400 hover:text-red-300"
        >
          Manage projects →
        </Link>
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

      {/* Aggregated feature tiles */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {TILES.map((tile) => {
          const Icon = tile.icon;
          const agg = features[tile.key];
          const total = agg?.total ?? 0;
          return (
            <Link
              key={tile.key}
              to={orgId ? resolveTileUrl(orgId, tile.to) : '#'}
              className="group rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur transition hover:border-zinc-600"
            >
              <div className="flex items-center justify-between">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-500/10 ring-1 ring-red-500/30">
                  <Icon className="h-5 w-5 text-red-400" />
                </div>
                <ArrowRight className="h-4 w-4 text-zinc-600 transition group-hover:translate-x-0.5 group-hover:text-zinc-300" />
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-zinc-100">{summary ? total : '…'}</span>
                <span className="text-xs font-semibold text-zinc-400">{tile.label}</span>
              </div>
              {tile.kind === 'events' ? (
                <SeverityBar dist={agg?.severity ?? {}} />
              ) : agg?.by_status ? (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {Object.entries(agg.by_status).map(([status, count]) => (
                    <span
                      key={status}
                      className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase ring-1 ${
                        status === 'connected'
                          ? 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30'
                          : status === 'error'
                            ? 'bg-red-500/15 text-red-400 ring-red-500/40'
                            : 'bg-zinc-800 text-zinc-400 ring-zinc-700'
                      }`}
                    >
                      {status}: {count}
                    </span>
                  ))}
                </div>
              ) : (
                <div className="mt-3 h-1.5 w-full rounded-full bg-zinc-800" />
              )}
              <p className="mt-2 text-xs leading-relaxed text-zinc-500">{tile.description}</p>
            </Link>
          );
        })}
      </div>

      {/* Gateway note */}
      <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3.5 text-xs leading-relaxed text-amber-300">
        <ScrollText className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span>
          <strong>Feeding this dashboard:</strong> scans arrive via the project gateway
          (<code className="font-mono">POST /api/v1/org/{orgId ?? '{org_id}'}/projects/&#123;slug&#125;/gateway</code>) and ingested
          logs via the same endpoint. Create project keys under Org Settings → API Keys. The legacy
          org-flat gateway is deprecated.
        </span>
      </div>
    </div>
  );
}

function resolveTileUrl(orgId: string, to: string): string {
  if (to.startsWith('..')) return `/org/${orgId}/${to.slice(3)}`; // '../logs' → '/org/:id/logs'
  return `/org/${orgId}/dashboard/${to}`;
}
