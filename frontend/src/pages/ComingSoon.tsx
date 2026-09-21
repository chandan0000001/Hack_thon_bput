import { Link } from 'react-router-dom';
import { ArrowLeft, Building2, Clock } from 'lucide-react';
import { useAuthStore } from '../store/authStore';

/**
 * Placeholder for frozen organization features (Phase -1).
 * Rendered when ORG_ENABLED=false server-side; reactivates with the Orgs Phase.
 */
export default function ComingSoon({
  title = 'Organization & Team',
  message,
}: {
  title?: string;
  message?: string;
}) {
  const orgEnabled = useAuthStore((s) => s.orgEnabled);

  // Feature-frozen mode (no explicit message): hide when orgs activate.
  // Workspace-guard mode (explicit message): always render the notice.
  if (!message && orgEnabled) return null; // re-activated; let the real page render

  return (
    <div className="cyber-grid flex min-h-[70vh] items-center justify-center px-4">
      <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900/90 p-8 text-center shadow-2xl backdrop-blur">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-zinc-800/60 ring-1 ring-zinc-700">
          <Building2 className="h-7 w-7 text-zinc-400" />
        </div>
        <h1 className="mt-4 font-mono text-lg font-bold tracking-wider text-zinc-100">{title}</h1>
        <div className="mx-auto mt-2 inline-flex items-center gap-1.5 rounded-md bg-zinc-800 px-2.5 py-1 font-mono text-[11px] font-bold tracking-wider text-zinc-300 ring-1 ring-zinc-700">
          <Clock className="h-3 w-3" /> ORG FEATURE
        </div>
        <p className="mt-4 text-sm leading-relaxed text-zinc-400">
          {message ??
            'Organization accounts — multi-analyzer workspaces, team roles, and shared queues — are on the roadmap. Your personal workspace is fully active in the meantime.'}
        </p>
        <Link
          to="/dashboard"
          className="mt-6 inline-flex items-center gap-1.5 text-xs text-zinc-400 transition hover:text-red-400"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
