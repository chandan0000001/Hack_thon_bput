import { useRef, useState } from 'react';
import { ArrowLeft, ChevronDown, ChevronRight, Loader2, Mail, Paperclip, PlayCircle, X } from 'lucide-react';
import * as api from '../services/api';
import type { AnalysisResult, RecommendedAction } from '../types';
import PageHeader from '../components/common/PageHeader';
import RiskGauge from '../components/common/RiskGauge';
import SeverityBadge from '../components/common/SeverityBadge';
import IndicatorTable from '../components/common/IndicatorTable';
import ExplanationPanel from '../components/common/ExplanationPanel';
import MitreTags from '../components/common/MitreTags';
import RecommendedActionsPanel from '../components/common/RecommendedActionsPanel';
import WarningsBanner from '../components/common/WarningsBanner';
import AuthVerificationPanel from '../components/common/AuthVerificationPanel';
import { PanelSkeleton } from '../components/common/LoadingSkeleton';
import { useUiStore } from '../store/uiStore';
import { useAuthStore } from '../store/authStore';

const BENIGN_SAMPLE = {
  sender: 'notices@university.edu',
  subject: 'Library hours update',
  body: 'The central library will remain open until 10 PM during examination week. No action is required from students.',
};

const PHISHING_SAMPLE = {
  sender: 'security-alert@micr0soft-verify.xyz',
  subject: 'URGENT: Verify your account immediately',
  body: 'Your account will be suspended within 24 hours. Click here http://185.220.101.7/login to verify your password and restore access. Failure to comply will result in permanent suspension.',
};

// Attachment demo payloads are generated client-side so the same upload
// pipeline that handles user files also handles the samples.
const BENIGN_ATTACHMENT_SAMPLE_FILE = new File(
  [
    'Employee Handbook — Welcome Guide\n\n' +
      'We are glad to have you on the team. Your onboarding buddy will walk you ' +
      'through the office facilities, the cafeteria timings and the library access policy. ' +
      'No action is required from you before your first day.',
  ],
  'welcome-guide.txt',
  { type: 'text/plain' },
);

const BENIGN_ATTACHMENT_SAMPLE = {
  ...BENIGN_SAMPLE,
  file: BENIGN_ATTACHMENT_SAMPLE_FILE,
};

const PHISHING_ATTACHMENT_SAMPLE_FILE = new File(
  [
    '<html><body>' +
      '<h2>Invoice Payment Confirmation — Account Suspended</h2>' +
      '<p>Dear customer, your invoice #INV-99213 could not be processed. ' +
      'Your account will be suspended within 24 hours unless you confirm your billing details.</p>' +
      '<p>Please enter your password and card number at the secure portal below:</p>' +
      '<p>http://185.220.101.7/secure-login — Secure Payment Portal</p>' +
      '<p>Failure to comply will result in permanent closure of your account.</p>' +
      '</body></html>',
  ],
  'invoice_confirmation.html',
  { type: 'text/html' },
);

const PHISHING_ATTACHMENT_SAMPLE = {
  ...PHISHING_SAMPLE,
  subject: 'URGENT: Invoice payment failed — action required',
  file: PHISHING_ATTACHMENT_SAMPLE_FILE,
};

export default function PhishingAnalysis() {
  const addToast = useUiStore((s) => s.addToast);
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [attachment, setAttachment] = useState<File | null>(null);
  const [analyzedAttachmentName, setAnalyzedAttachmentName] = useState<string | null>(null);
  const [rawHeaders, setRawHeaders] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [showResult, setShowResult] = useState(false);
  const readOnly = !useAuthStore((s) => s.can('analyze'));


  const analyze = async () => {
    if (!sender.trim() || !body.trim()) {
      addToast('Sender and email body are required', 'medium');
      return;
    }
    setLoading(true);
    setAnalyzedAttachmentName(attachment?.name ?? null);
    setShowResult(true);
    try {
      const res = attachment
        ? await api.analyzeEmailWithAttachment(sender, subject, body, attachment)
        : await api.analyzeEmail(sender, subject, body, rawHeaders);
      setResult(res);
      addToast(`Analysis complete: risk ${res.riskScore}/100 (${res.severity})`, res.severity);
    } catch (err) {
      setShowResult(false);
      addToast(err instanceof Error ? err.message : 'Analysis failed. Please try again.', 'high');
    } finally {
      setLoading(false);
    }
  };

  const handleExecute = (actionId: string) => {
    const action = result?.recommendedActions.find((a: RecommendedAction) => a.id === actionId);
    addToast(`Action acknowledged: ${action?.action ?? actionId}`, 'safe');
  };

  return (
    <div>
      {showResult ? (
        /* Full-width report view — replaces the form area after Analyze */
        <div>
          <div className="mb-5 flex flex-wrap items-center gap-4">
            <button
              onClick={() => setShowResult(false)}
              className="flex items-center gap-1.5 rounded-lg bg-zinc-700/50 px-3.5 py-2 text-xs font-semibold text-zinc-200 ring-1 ring-zinc-600/50 hover:bg-zinc-700"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to Editor
            </button>
            <div>
              <h2 className="text-xl font-bold text-zinc-100">Analysis Report</h2>
              <p className="mt-0.5 text-sm text-zinc-400">
                Verdict, evidence and recommended response for the analyzed email.
              </p>
            </div>
          </div>

          <div className="space-y-4">
            {loading && (
              <div className="rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-5 backdrop-blur">
                <div className="mb-4 flex items-center gap-2 text-sm text-zinc-400">
                  <Loader2 className="h-4 w-4 animate-spin text-red-400" />
                  Running phishing detection pipeline...
                </div>
                <PanelSkeleton rows={5} />
                <div className="mt-4">
                  <PanelSkeleton rows={3} />
                </div>
              </div>
            )}

            {!loading && result && (
              <>
                <div className="flex flex-wrap items-center gap-6 rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-5 backdrop-blur">
                  <RiskGauge score={result.riskScore} size="lg" />
                  <div className="space-y-2">
                    <SeverityBadge severity={result.severity} />
                    <div className="text-xs text-zinc-400">
                      Threat type: <span className="text-zinc-200">{result.threatType}</span>
                    </div>
                    <div className="text-xs text-zinc-400">
                      Confidence: <span className="font-mono font-semibold text-red-400">{result.confidence}%</span>
                    </div>
                    <div className="text-xs text-zinc-400">
                      Event: <span className="font-mono text-zinc-300">{result.eventId}</span>
                    </div>
                  </div>
                </div>
                <WarningsBanner warnings={result.warnings} />
                <AuthVerificationPanel verification={result.authVerification} />
                <IndicatorTable indicators={result.indicators} attachmentName={analyzedAttachmentName} />
                <div className="grid gap-4 lg:grid-cols-2">
                  <ExplanationPanel explanation={result.explanation} confidence={result.confidence} />
                  <div className="space-y-4">
                    <div>
                      <h3 className="mb-2 text-sm font-semibold text-zinc-200">MITRE ATT&CK Mapping</h3>
                      <MitreTags techniques={result.mitreTechniques} />
                    </div>
                    <div>
                      <h3 className="mb-2 text-sm font-semibold text-zinc-200">Recommended Response</h3>
                      <RecommendedActionsPanel actions={result.recommendedActions} onExecute={handleExecute} />
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      ) : (
        <>
          <PageHeader
            title="AI-Powered Phishing Detection"
            description="Analyze emails for phishing, social engineering and credential harvesting using heuristic indicators."
          />
          {readOnly && (
            <div className="rounded-lg border border-red-400/40 bg-red-400/10 px-3.5 py-2 text-xs text-red-400">
              Read-only role — mutation actions are disabled. Contact an administrator for elevated access.
            </div>
          )}

          <div>
        {/* Input form */}
        <div className="rounded-xl border border-zinc-700/50 bg-zinc-800/60 p-5 backdrop-blur">
          <div className="mb-4 flex items-center gap-2">
            <Mail className="h-4 w-4 text-red-400" />
            <h3 className="text-sm font-semibold text-zinc-100">Email Content</h3>
          </div>

          <div className="space-y-3.5">
            <div>
              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">Sender Address</label>
              <input
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder="sender@example-domain.com"
                className="w-full rounded-lg border border-zinc-700/60 bg-zinc-800/60 px-3 py-2 font-mono text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-red-500/60"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">Subject</label>
              <input
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="Email subject line"
                className="w-full rounded-lg border border-zinc-700/60 bg-zinc-800/60 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-red-500/60"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-zinc-400">Email Body</label>
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                rows={8}
                placeholder="Paste the full email body here..."
                className="w-full resize-y rounded-lg border border-zinc-700/60 bg-zinc-800/60 px-3 py-2 text-sm leading-relaxed text-zinc-100 placeholder-zinc-600 outline-none focus:border-red-500/60"
              />
            </div>

            {/* Advanced: raw RFC 5322 headers — enable real SPF/DKIM/DMARC verification */}
            <div className="rounded-lg border border-zinc-700/60 bg-zinc-900/40">
              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-xs font-medium text-zinc-300 hover:text-zinc-100"
              >
                {showAdvanced ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                Advanced — supply raw message headers
                <span className="ml-auto font-mono text-[10px] uppercase tracking-wider text-zinc-600">
                  optional
                </span>
              </button>
              {showAdvanced && (
                <div className="px-3 pb-3">
                  <textarea
                    value={rawHeaders}
                    onChange={(e) => setRawHeaders(e.target.value)}
                    rows={8}
                    placeholder="Paste full RFC 5322 headers here. Without them SPF/DKIM/DMARC cannot be verified."
                    className="w-full resize-y rounded-lg border border-zinc-700/60 bg-zinc-800/60 px-3 py-2 font-mono text-xs leading-relaxed text-zinc-100 placeholder-zinc-600 outline-none focus:border-red-500/60"
                  />
                  <p className="mt-1.5 text-[11px] text-zinc-500">
                    Authentication-Result, Received and DKIM-Signature blocks from the original
                    message enable independent SPF/DKIM/DMARC verification.
                  </p>
                </div>
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => {
                  setSender(BENIGN_SAMPLE.sender);
                  setSubject(BENIGN_SAMPLE.subject);
                  setBody(BENIGN_SAMPLE.body);
                  setAttachment(null);
                }}
                className="rounded-lg bg-zinc-700/50 px-3 py-1.5 text-xs font-medium text-zinc-300 ring-1 ring-zinc-600/50 hover:bg-zinc-700"
              >
                Load Benign Sample
              </button>
              <button
                onClick={() => {
                  setSender(PHISHING_SAMPLE.sender);
                  setSubject(PHISHING_SAMPLE.subject);
                  setBody(PHISHING_SAMPLE.body);
                  setAttachment(null);
                }}
                className="rounded-lg bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400 ring-1 ring-red-500/40 hover:bg-red-500/20"
              >
                Load Phishing Sample
              </button>
              <button
                onClick={() => {
                  setSender(BENIGN_ATTACHMENT_SAMPLE.sender);
                  setSubject(BENIGN_ATTACHMENT_SAMPLE.subject);
                  setBody(BENIGN_ATTACHMENT_SAMPLE.body);
                  setAttachment(BENIGN_ATTACHMENT_SAMPLE.file);
                }}
                className="rounded-lg bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-400 ring-1 ring-emerald-500/40 hover:bg-emerald-500/20"
              >
                Benign + Attachment
              </button>
              <button
                onClick={() => {
                  setSender(PHISHING_ATTACHMENT_SAMPLE.sender);
                  setSubject(PHISHING_ATTACHMENT_SAMPLE.subject);
                  setBody(PHISHING_ATTACHMENT_SAMPLE.body);
                  setAttachment(PHISHING_ATTACHMENT_SAMPLE.file);
                }}
                className="rounded-lg bg-orange-500/10 px-3 py-1.5 text-xs font-medium text-orange-400 ring-1 ring-orange-500/40 hover:bg-orange-500/20"
              >
                Phishing + Attachment
              </button>
            </div>

            {/* Attachment picker — scans any file from the local system */}
            <div>
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  setAttachment(e.target.files?.[0] ?? null);
                  e.target.value = '';
                }}
              />
              <div className="flex items-center gap-2">
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={readOnly}
                  title={readOnly ? 'Read-only role' : 'Attach a file from your system'}
                  className="flex items-center gap-1.5 rounded-lg border border-dashed border-zinc-600/70 px-3 py-1.5 text-xs font-medium text-zinc-300 hover:border-red-500/60 hover:text-red-400 disabled:opacity-60"
                >
                  <Paperclip className="h-3.5 w-3.5" />
                  Attach file from system
                </button>
                {attachment && (
                  <span className="flex items-center gap-1.5 rounded-lg bg-zinc-700/40 px-2.5 py-1.5 text-xs text-zinc-200 ring-1 ring-zinc-600/50">
                    <Paperclip className="h-3 w-3 text-zinc-400" />
                    <span className="max-w-52 truncate font-mono">{attachment.name}</span>
                    <span className="text-zinc-500">{(attachment.size / 1024).toFixed(1)} KB</span>
                    <button
                      onClick={() => setAttachment(null)}
                      title="Remove attachment"
                      className="text-zinc-500 hover:text-red-400"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </span>
                )}
              </div>
              {attachment && (
                <p className="mt-1.5 text-[11px] text-zinc-500">
                  The attachment will run through the full malware + content scan pipeline.
                </p>
              )}
            </div>

            <button
              onClick={analyze}
              disabled={loading || readOnly}
              title={readOnly ? 'Read-only role' : undefined}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-red-600 py-2.5 text-sm font-bold text-white hover:bg-red-500 disabled:opacity-60"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
              {loading ? 'Analyzing...' : 'Analyze Email'}
            </button>
          </div>
        </div>

          </div>
        </>
      )}
    </div>
  );
}
