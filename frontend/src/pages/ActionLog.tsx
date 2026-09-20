import { useState } from 'react';
import { RefreshCw, ScrollText, XCircle } from 'lucide-react';
import * as api from '../services/api';
import { useApi } from '../hooks/useApi';
import type { ActionExecution, ActionExecutionStatus } from '../types';
import PageHeader from '../components/common/PageHeader';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusPill from '../components/common/StatusPill';
import DataTable, { type Column } from '../components/common/DataTable';
import EmptyState from '../components/common/EmptyState';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';
import { MODULE_LABELS } from '../constants';
import { formatLocal } from '../utils/datetime';

const STATUS_OPTIONS: (ActionExecutionStatus | '')[] = [
  '', 'pending', 'success', 'rejected', 'released', 'unblocked', 'skipped', 'failed',
];
const MODULE_OPTIONS = ['phishing', 'url', 'impersonation', 'account_takeover', 'network', 'api_abuse', 'deepfake'];
const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low'];
const PAGE_SIZE = 20;

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  options: string[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-300 outline-none focus:border-red-500/60"
    >
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {o.replace(/_/g, ' ')}
        </option>
      ))}
    </select>
  );
}

export default function ActionLog() {
  const [status, setStatus] = useState('');
  const [module, setModule] = useState('');
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<ActionExecution | null>(null);

  const { data, loading, error, refetch } = useApi(
    () =>
      api.listActions({
        status: status || undefined,
        module: module || undefined,
        severity: severity || undefined,
        page,
        page_size: PAGE_SIZE,
      }),
    [status, module, severity, page]
  );

  const columns: Column<ActionExecution>[] = [
    { key: 'action', header: 'Action', render: (e) => <span className="font-mono text-xs text-red-400">{e.action_type}</span>, sortValue: (e) => e.action_type },
    { key: 'status', header: 'Status', render: (e) => <StatusPill status={e.status} />, sortValue: (e) => e.status },
    { key: 'module', header: 'Module', render: (e) => <span className="text-xs text-zinc-400">{MODULE_LABELS[e.module as keyof typeof MODULE_LABELS] ?? e.module}</span>, sortValue: (e) => e.module },
    { key: 'risk', header: 'Risk', render: (e) => <span className="font-mono font-semibold text-zinc-100">{e.risk_score}</span>, sortValue: (e) => e.risk_score },
    { key: 'severity', header: 'Severity', render: (e) => <SeverityBadge severity={e.severity} />, sortValue: (e) => e.severity },
    { key: 'mode', header: 'Mode', render: (e) => <span className="text-xs text-zinc-500">{e.execution_mode}</span>, sortValue: (e) => e.execution_mode },
    { key: 'trigger', header: 'Triggered By', render: (e) => <span className="font-mono text-[11px] text-zinc-500">{e.triggered_by}{e.triggered_by_id ? ` · ${e.triggered_by_id}` : ''}</span> },
    { key: 'created', header: 'Timestamp', render: (e) => <span className="text-xs text-zinc-500">{formatLocal(e.created_at)}</span>, sortValue: (e) => e.created_at },
  ];

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const filtersActive = Boolean(status || module || severity);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Action Log"
        description="Master audit view of every enforcement action — auto-executed, approved, rejected, released and skipped."
        actions={
          <button
            onClick={refetch}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 transition"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        }
      />

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <FilterSelect value={status} onChange={(v) => { setStatus(v); setPage(1); }} placeholder="all statuses" options={STATUS_OPTIONS.filter(Boolean)} />
        <FilterSelect value={module} onChange={(v) => { setModule(v); setPage(1); }} placeholder="all modules" options={MODULE_OPTIONS} />
        <FilterSelect value={severity} onChange={(v) => { setSeverity(v); setPage(1); }} placeholder="all severities" options={SEVERITY_OPTIONS} />
        {filtersActive && (
          <button
            onClick={() => { setStatus(''); setModule(''); setSeverity(''); setPage(1); }}
            className="text-xs text-red-400 hover:text-red-300"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto font-mono text-[11px] text-zinc-600">{data?.total ?? 0} records</span>
      </div>

      {loading ? (
        <PanelSkeleton height="h-72" />
      ) : error ? (
        <EmptyState icon={XCircle} title="Failed to load the action log" description={error} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="No action executions found"
          description={filtersActive ? 'No records match the current filters.' : 'Enforcement actions will appear here as integrations fire.'}
        />
      ) : (
        <>
          <DataTable
            columns={columns}
            data={data.items}
            rowKey={(e) => e.id}
            onRowClick={(e) => setSelected(selected?.id === e.id ? null : e)}
            emptyMessage="No records"
          />

          {selected && (
            <div className="rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <h3 className="font-mono text-sm font-semibold text-zinc-100">{selected.action_type}</h3>
                  <StatusPill status={selected.status} />
                </div>
                <span className="font-mono text-[11px] text-zinc-500">{selected.id}</span>
              </div>
              <div className="mt-3 grid gap-3 text-xs md:grid-cols-2">
                <div>
                  <p className="font-semibold uppercase tracking-wider text-zinc-500">Target</p>
                  <pre className="mt-1 overflow-x-auto rounded-lg bg-zinc-900 p-2 font-mono text-[11px] text-zinc-300">
                    {JSON.stringify(selected.target ?? {}, null, 2)}
                  </pre>
                </div>
                <div className="space-y-2">
                  <div>
                    <p className="font-semibold uppercase tracking-wider text-zinc-500">Execution Result</p>
                    <pre className="mt-1 overflow-x-auto rounded-lg bg-zinc-900 p-2 font-mono text-[11px] text-zinc-300">
                      {selected.execution_result ? JSON.stringify(selected.execution_result, null, 2) : '—'}
                    </pre>
                  </div>
                  {selected.rejection_reason && (
                    <p className="text-zinc-300">
                      <span className="text-zinc-500">Rejection reason:</span> {selected.rejection_reason}
                    </p>
                  )}
                  {selected.approved_by && (
                    <p className="text-zinc-300">
                      <span className="text-zinc-500">{selected.status === 'rejected' ? 'Reviewed by' : 'Approved by'}:</span>{' '}
                      <span className="font-mono">{selected.approved_by}</span>
                      {selected.approved_at ? ` · ${formatLocal(selected.approved_at)}` : ''}
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-3 text-xs text-zinc-400">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="rounded-lg border border-zinc-700 px-3 py-1.5 hover:bg-zinc-800 disabled:opacity-40 transition"
              >
                Previous
              </button>
              <span className="font-mono">
                page {data?.page ?? page} / {totalPages}
              </span>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="rounded-lg border border-zinc-700 px-3 py-1.5 hover:bg-zinc-800 disabled:opacity-40 transition"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
