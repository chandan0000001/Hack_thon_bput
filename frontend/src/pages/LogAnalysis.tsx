import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Loader2, Terminal, Wand2 } from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import SeverityBadge from '../components/common/SeverityBadge';
import IndicatorList from '../components/common/IndicatorList';
import ExplanationPanel from '../components/common/ExplanationPanel';
import RecommendedActionsPanel from '../components/common/RecommendedActionsPanel';
import MitreTags from '../components/common/MitreTags';
import * as api from '../services/api';
import { useUiStore } from '../store/uiStore';
import type { AnalysisResult } from '../types';

const AUTH_LOG_SAMPLE = `[
  {"user": "alice", "ip": "203.0.113.10", "location": "Berlin", "device": "win-11", "status": "success", "timestamp": "2026-09-13T08:59:00Z"},
  {"user": "alice", "ip": "198.51.100.7", "location": "Lagos", "device": "linux", "status": "failed", "timestamp": "2026-09-13T09:00:30Z"},
  {"user": "alice", "ip": "198.51.100.7", "location": "Lagos", "device": "linux", "status": "failed", "timestamp": "2026-09-13T09:01:10Z"},
  {"user": "alice", "ip": "198.51.100.7", "location": "Lagos", "device": "linux", "status": "success", "timestamp": "2026-09-13T09:02:00Z"}
]`;

const NETWORK_FLOW_SAMPLE = `[
  {"sourceIp": "10.0.0.15", "destIp": "185.220.101.9", "port": 4444, "bytesOut": 850000000, "protocol": "TCP"},
  {"sourceIp": "10.0.0.15", "destIp": "185.220.101.9", "port": 22, "bytesOut": 1200000, "protocol": "TCP"}
]`;

type LogKind = 'auth' | 'network' | null;

function detectLogKind(parsed: unknown): LogKind {
  if (!Array.isArray(parsed) || parsed.length === 0) return null;
  const first = parsed[0];
  if (typeof first !== 'object' || first === null) return null;
  const keys = new Set(Object.keys(first as Record<string, unknown>));
  const authKeys = ['user', 'ip', 'location', 'device', 'status', 'timestamp'];
  const netKeys = ['sourceIp', 'destIp', 'port', 'bytesOut', 'protocol'];
  if (authKeys.every((k) => keys.has(k))) return 'auth';
  if (netKeys.every((k) => keys.has(k))) return 'network';
  return null;
}

/**
 * Generic log paste-box (Excalidraw step-1 client feature #6): paste an
 * auth-log or network-flow JSON array, CYBERGUARD detects the format and runs
 * the existing ATO / network detectors — analysis only, real results.
 */
export default function LogAnalysis() {
  const addToast = useUiStore((s) => s.addToast);
  const [pasted, setPasted] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detected, setDetected] = useState<LogKind>(null);

  const runAnalysis = useCallback(
    async (text: string) => {
      setError(null);
      setResult(null);
      setDetected(null);

      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        setError('Invalid JSON — paste an auth-log or network-flow JSON array.');
        return;
      }

      const kind = detectLogKind(parsed);
      setDetected(kind);
      if (kind === null) {
        setError('Unsupported log format — expected an auth-log or network-flow JSON array.');
        return;
      }

      setAnalyzing(true);
      try {
        if (kind === 'auth') {
          setResult(await api.analyzeAuthLog(parsed as Parameters<typeof api.analyzeAuthLog>[0]));
        } else {
          setResult(await api.analyzeNetworkFlow(parsed as Parameters<typeof api.analyzeNetworkFlow>[0]));
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Analysis failed';
        setError(`Analysis failed: ${message}`);
        addToast(`Log analysis failed: ${message}`, 'high');
      } finally {
        setAnalyzing(false);
      }
    },
    [addToast],
  );

  // No auto-filled samples, no auto-analysis: the user pastes and acts.
  useEffect(() => {
    setResult(null);
    setError(null);
    setDetected(null);
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Log Analysis"
        description="Paste an authentication log or network-flow JSON array — CYBERGUARD detects the format and runs the matching detection engine. Analysis only; nothing is executed."
      />

      <div className="rounded-2xl border border-zinc-800 bg-zinc-900/90 p-5 shadow-sm backdrop-blur">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
            <Terminal className="h-4 w-4 text-red-400" /> Paste your log
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">format hints:</span>
            <button
              type="button"
              onClick={() => setPasted(AUTH_LOG_SAMPLE)}
              className="rounded bg-zinc-800 px-2 py-1 font-mono text-[10px] text-zinc-300 ring-1 ring-zinc-700 transition hover:text-red-400"
            >
              auth-log JSON sample
            </button>
            <button
              type="button"
              onClick={() => setPasted(NETWORK_FLOW_SAMPLE)}
              className="rounded bg-zinc-800 px-2 py-1 font-mono text-[10px] text-zinc-300 ring-1 ring-zinc-700 transition hover:text-red-400"
            >
              network-flow JSON sample
            </button>
          </div>
        </div>

        <textarea
          value={pasted}
          onChange={(e) => setPasted(e.target.value)}
          rows={10}
          spellCheck={false}
          placeholder={'Paste a JSON array here, e.g.\n[\n  {"user": "alice", "ip": "203.0.113.10", "location": "Berlin", "device": "win-11", "status": "failed", "timestamp": "…"}\n]'}
          className="w-full resize-y rounded-xl border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs leading-relaxed text-zinc-100 placeholder-zinc-600 outline-none transition focus:border-red-500/60 focus:ring-1 focus:ring-red-500/40"
        />

        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => runAnalysis(pasted)}
            disabled={analyzing || !pasted.trim()}
            className="flex items-center gap-2 rounded-lg bg-red-600 px-5 py-2.5 text-sm font-bold text-white shadow-lg shadow-red-600/20 transition hover:bg-red-500 disabled:opacity-50"
          >
            {analyzing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
            {analyzing ? 'Analyzing…' : 'Detect & Analyze'}
          </button>
          {detected && !error && (
            <span className="rounded bg-emerald-500/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-emerald-400 ring-1 ring-emerald-500/30">
              detected: {detected === 'auth' ? 'auth-log → account-takeover engine' : 'network-flow → network engine'}
            </span>
          )}
          <span className="font-mono text-[10px] text-zinc-600">
            {pasted.trim().length} chars pasted
          </span>
        </div>

        {error && (
          <div className="mt-3 flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-sm text-red-300">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            {error}
          </div>
        )}
      </div>

      {/* Results — same verbose presentation as the other analysis pages */}
      {analyzing && (
        <div className="flex items-center justify-center gap-2 rounded-2xl border border-zinc-800 bg-zinc-900/90 px-5 py-10 text-sm text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Running the detection engine…
        </div>
      )}

      {!analyzing && result && (
        <div className="space-y-4">
          <div className="flex items-center gap-4 rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-4 backdrop-blur">
            <span
              className="text-3xl font-bold"
              style={{
                color:
                  result.severity === 'critical' || result.severity === 'high'
                    ? '#ef4444'
                    : result.severity === 'medium'
                      ? '#a3a3a3'
                      : '#e4e4e7',
              }}
            >
              {result.riskScore}
            </span>
            <div className="space-y-1">
              <SeverityBadge severity={result.severity} />
              <div className="text-xs text-zinc-400">
                {result.indicators.length} indicators — event <span className="font-mono text-zinc-300">{result.eventId}</span>
              </div>
            </div>
          </div>

          {result.mitreTechniques.length > 0 && <MitreTags techniques={result.mitreTechniques} />}
          <IndicatorList indicators={result.indicators} />
          <ExplanationPanel
            explanation={result.explanation}
            confidence={result.confidence}
            eventId={result.eventId}
            onExplanationLoaded={(exp) => setResult((prev) => (prev ? { ...prev, explanation: exp } : prev))}
          />
          <RecommendedActionsPanel
            actions={result.recommendedActions}
            onExecute={(actionId) => {
              const action = result.recommendedActions.find((a) => a.id === actionId);
              addToast(
                `Analysis-only phase: "${action?.action ?? actionId}" was recommended, not executed.`,
                'medium',
              );
            }}
          />
        </div>
      )}
    </div>
  );
}
