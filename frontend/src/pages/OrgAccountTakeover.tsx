/**
 * SCENARIO-3 — org-scoped Account Takeover & Abnormal Behaviour analysis.
 *
 * Hosted inside OrgWorkspaceShell (route
 * /org/:orgId/projects/:projectId/analysis/account-takeover). The analysis
 * request carries ONLY the baseline profile + abnormal activity timeline:
 * the backend resolves the organization/project server-side from the JWT
 * (validated X-Organization-Id header), so no client-supplied org scope.
 *
 * Result view: vertical timeline (red dots for flagged events), fused
 * indicators, recommended response and the XAI explanation panel.
 */

import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Clock, Play, ShieldAlert } from 'lucide-react';
import { orgApi, type AtoAnalysisResult } from '../services/orgApi';
import ExplanationPanel from '../components/common/ExplanationPanel';
import {
  ATO_DEMO_BASELINE,
  ATO_DEMO_TIMELINE,
  atoClockLabel,
  atoDotClass,
  atoLevelTone,
  sortAtoTimeline,
} from './orgAtoHelpers';

export default function OrgAccountTakeover() {
  const { orgId } = useParams<{ orgId: string; projectId: string }>();
  const [accountId, setAccountId] = useState(ATO_DEMO_BASELINE.account_id);
  const [loginStart, setLoginStart] = useState(
    ATO_DEMO_BASELINE.baseline_profile.typical_login_start ?? '09:00'
  );
  const [loginEnd, setLoginEnd] = useState(
    ATO_DEMO_BASELINE.baseline_profile.typical_login_end ?? '10:00'
  );
  const [country, setCountry] = useState(
    ATO_DEMO_BASELINE.baseline_profile.home_country ?? 'US'
  );
  const [knownIps, setKnownIps] = useState(
    ATO_DEMO_BASELINE.baseline_profile.known_ips.join(', ')
  );
  const [knownDevices, setKnownDevices] = useState(
    ATO_DEMO_BASELINE.baseline_profile.known_devices.join(', ')
  );
  const [timelineJson, setTimelineJson] = useState(JSON.stringify(ATO_DEMO_TIMELINE, null, 2));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AtoAnalysisResult | null>(null);

  async function runAnalysis() {
    if (!orgId) return;
    let events: unknown;
    try {
      events = JSON.parse(timelineJson);
    } catch {
      setError('Activity timeline is not valid JSON.');
      return;
    }
    if (!Array.isArray(events)) {
      setError('Activity timeline must be a JSON array of events.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const payload = {
        source: 'org_dashboard',
        account_id: accountId,
        baseline_profile: {
          user: accountId,
          typical_login_start: loginStart,
          typical_login_end: loginEnd,
          home_country: country,
          known_ips: knownIps
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
          known_devices: knownDevices
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
        },
        suspicious_events: events,
      };
      setResult(await orgApi.analyzeAccountTakeover(orgId, payload));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis request failed.');
    } finally {
      setLoading(false);
    }
  }

  const tone = result ? atoLevelTone(result.risk_level) : null;
  const timeline = result ? sortAtoTimeline(result.suspicious_events) : [];

  return (
    <div className="p-6 space-y-5" data-testid="org-ato-page">
      <div>
        <h1 className="text-lg font-semibold text-zinc-100">Account Takeover</h1>
        <p className="mt-1 text-sm text-zinc-500">
          Compare an abnormal activity timeline against the account's normal baseline
          (rules + anomaly detection + threat intel). Organization scope is resolved
          server-side from your session.
        </p>
      </div>

      {/* Baseline profile */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-4">
        <div className="text-sm text-zinc-300">Normal baseline</div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <label className="text-xs text-zinc-500 space-y-1">
            <span>Account</span>
            <input
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              data-testid="ato-account-input"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            />
          </label>
          <label className="text-xs text-zinc-500 space-y-1">
            <span>Usual login window (start–end)</span>
            <div className="flex items-center gap-2">
              <input
                value={loginStart}
                onChange={(e) => setLoginStart(e.target.value)}
                data-testid="ato-login-start-input"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
              />
              <span className="text-zinc-600">–</span>
              <input
                value={loginEnd}
                onChange={(e) => setLoginEnd(e.target.value)}
                data-testid="ato-login-end-input"
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
              />
            </div>
          </label>
          <label className="text-xs text-zinc-500 space-y-1">
            <span>Home country</span>
            <input
              value={country}
              onChange={(e) => setCountry(e.target.value)}
              data-testid="ato-country-input"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            />
          </label>
          <label className="text-xs text-zinc-500 space-y-1">
            <span>Known devices (comma-separated)</span>
            <input
              value={knownDevices}
              onChange={(e) => setKnownDevices(e.target.value)}
              data-testid="ato-devices-input"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            />
          </label>
          <label className="text-xs text-zinc-500 space-y-1 sm:col-span-2">
            <span>Known IPs (comma-separated)</span>
            <input
              value={knownIps}
              onChange={(e) => setKnownIps(e.target.value)}
              data-testid="ato-ips-input"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
            />
          </label>
        </div>
      </div>

      {/* Suspicious activity timeline (JSON) */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-sm text-zinc-300">Abnormal activity timeline</div>
          <button
            type="button"
            onClick={() => setTimelineJson(JSON.stringify(ATO_DEMO_TIMELINE, null, 2))}
            data-testid="ato-load-demo-btn"
            className="text-xs rounded-lg border border-zinc-700 px-2.5 py-1 text-zinc-300 hover:bg-zinc-800"
          >
            Load demo attack timeline
          </button>
        </div>
        <textarea
          value={timelineJson}
          onChange={(e) => setTimelineJson(e.target.value)}
          rows={12}
          spellCheck={false}
          data-testid="ato-timeline-input"
          className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200"
        />
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={runAnalysis}
            disabled={loading}
            data-testid="ato-run-btn"
            className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-500 disabled:opacity-50"
          >
            <Play style={{ width: 14, height: 14 }} />
            {loading ? 'Analyzing…' : 'Run Analysis'}
          </button>
          {error && (
            <span className="text-sm text-red-400" data-testid="ato-error">
              {error}
            </span>
          )}
        </div>
      </div>

      {/* Result */}
      {result && (
        <div className="space-y-5" data-testid="ato-result">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 flex items-center gap-4">
            <ShieldAlert
              className={result.verdict === 'account_takeover_detected' ? 'text-red-400' : 'text-emerald-400'}
              style={{ width: 28, height: 28 }}
            />
            <div>
              <div className="text-sm text-zinc-200" data-testid="ato-verdict">
                {result.verdict === 'account_takeover_detected'
                  ? 'Possible account takeover detected'
                  : 'No account takeover detected'}
              </div>
              <div className="text-xs text-zinc-500">
                org {result.organization.name}
                {result.project ? ` · project ${result.project.id.slice(0, 8)}…` : ''}
              </div>
            </div>
            <span
              className={`ml-auto rounded-full px-3 py-1 text-xs font-semibold ring-1 ${tone?.ring} ${tone?.text}`}
              data-testid="ato-risk-pill"
            >
              {tone?.label} · {result.risk_score}/100
            </span>
          </div>

          {/* Vertical timeline */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="text-sm text-zinc-300 mb-4">Activity timeline</div>
            <div className="relative ml-3 border-l-2 border-zinc-800 space-y-6" data-testid="ato-timeline">
              {timeline.map((event, idx) => (
                <div key={idx} className="relative pl-6" data-testid="ato-timeline-item">
                  <span
                    className={`absolute -left-[8px] top-1 h-4 w-4 rounded-full ring-4 ring-zinc-950 ${atoDotClass(event)}`}
                  />
                  <div className="flex items-center gap-2 text-sm text-zinc-200">
                    <Clock className="h-3.5 w-3.5 text-zinc-500" style={{ width: 14, height: 14 }} />
                    <span className="font-mono" data-testid="ato-timeline-time">
                      {atoClockLabel(event.timestamp)}
                    </span>
                    <span className="text-zinc-400">{event.detail || String(event.event_type ?? 'event')}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {(event.flagged ?? []).map((flag) => (
                      <span
                        key={flag}
                        className="rounded bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-300 ring-1 ring-red-500/30"
                      >
                        {flag.split('_').join(' ')}
                      </span>
                    ))}
                    {typeof event.event_score === 'number' && event.event_score > 0 && (
                      <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">
                        +{event.event_score} risk
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Indicators */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="text-sm text-zinc-300 mb-3">Detected indicators</div>
            <ul className="space-y-2" data-testid="ato-indicators">
              {result.indicators.map((indicator, idx) => (
                <li key={idx} className="flex items-start gap-2 text-sm">
                  <span className={indicator.severity === 'critical' || indicator.severity === 'high' ? 'text-red-400' : 'text-amber-400'}>
                    ✗
                  </span>
                  <span className="text-zinc-300">{indicator.description}</span>
                  <span className="ml-auto text-[10px] uppercase tracking-wider text-zinc-600">
                    {indicator.signal}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          {/* Recommended response */}
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
            <div className="text-sm font-semibold text-emerald-300 mb-2">Recommended response</div>
            <ol className="list-decimal space-y-1 pl-5 text-sm text-zinc-300" data-testid="ato-actions">
              {result.recommended_actions.map((action, idx) => (
                <li key={idx}>{action}</li>
              ))}
            </ol>
          </div>

          <ExplanationPanel
            explanation={result.explanation}
            confidence={result.risk_score}
            eventId={result.alert_id}
          />
        </div>
      )}
    </div>
  );
}
