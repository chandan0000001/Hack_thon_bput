/**
 * Single source of truth for workspace-scoped navigation (Excalidraw step-1
 * design). Sidebar rendering AND route guards both consume this file — there
 * are no duplicated nav lists anywhere else.
 *
 * Scope mapping (default; flip an item's `scope` to move it):
 *   Dashboard, Phishing, URL, Impersonation, Deepfake ............ both
 *   Log Analysis (paste-box) ..................................... both
 *   Email Connectors, Quarantine, Blocked Senders, Security History,
 *   Notification Log, Settings ................................... both
 *   Account Takeover, Network & API .............................. org
 *   Alerts, Incidents, Response Actions, Audit Logs, Reports ..... org
 *   Approvals, Block List, Action Log, Policies, Org Mgmt ........ org
 *   Admin Users .................................................. org (admin-gated)
 */

import {
  Ban,
  Bell,
  ClipboardCheck,
  FileBarChart,
  KeyRound,
  LayoutDashboard,
  LinkIcon,
  Mail,
  Network,
  PackageOpen,
  ScrollText,
  Settings,
  Settings2,
  ShieldAlert,
  Terminal,
  UserX,
  Video,
  Zap,
} from './components/layout/navIcons';

export type NavScope = 'user' | 'org' | 'both';
export type NavSection = 'analyze' | 'mailbox' | 'history' | 'org' | 'system';

export interface NavItem {
  to: string;
  label: string;
  icon: typeof Bell;
  scope: NavScope;
  section: NavSection;
  adminOnly?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  // --- analyze (both workspaces) ---
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, scope: 'both', section: 'analyze' },
  { to: '/phishing', label: 'Phishing Analysis', icon: Mail, scope: 'both', section: 'analyze' },
  { to: '/url-analysis', label: 'URL Analysis', icon: LinkIcon, scope: 'both', section: 'analyze' },
  { to: '/impersonation', label: 'Impersonation', icon: UserX, scope: 'both', section: 'analyze' },
  { to: '/deepfake', label: 'Deepfake Detection', icon: Video, scope: 'both', section: 'analyze' },
  { to: '/log-analysis', label: 'Log Analysis', icon: Terminal, scope: 'both', section: 'analyze' },
  // --- analyze (org-side modules) ---
  { to: '/account-takeover', label: 'Account Takeover', icon: KeyRound, scope: 'org', section: 'analyze' },
  { to: '/network-threats', label: 'Network & API', icon: Network, scope: 'org', section: 'analyze' },
  // --- mailbox (both) ---
  { to: '/email-connectors', label: 'Email Connectors', icon: Mail, scope: 'both', section: 'mailbox' },
  { to: '/quarantine', label: 'Quarantine Queue', icon: PackageOpen, scope: 'both', section: 'mailbox' },
  { to: '/blocked-senders', label: 'Blocked Senders', icon: Ban, scope: 'both', section: 'mailbox' },
  // --- history (both) ---
  { to: '/security-history', label: 'Security History', icon: ScrollText, scope: 'both', section: 'history' },
  { to: '/notification-log', label: 'Notification Log', icon: Bell, scope: 'both', section: 'history' },
  { to: '/audit-logs', label: 'Audit Logs', icon: ScrollText, scope: 'org', section: 'history' },
  // --- org (organization workspace) ---
  { to: '/org/dashboard', label: 'Organization Dashboard', icon: LayoutDashboard, scope: 'org', section: 'org' },
  { to: '/org/events', label: 'Events', icon: ShieldAlert, scope: 'org', section: 'org' },
  { to: '/org/settings', label: 'Project Settings', icon: Settings, scope: 'org', section: 'org' },
  { to: '/alerts', label: 'Alerts', icon: Bell, scope: 'org', section: 'org' },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert, scope: 'org', section: 'org' },
  { to: '/response-actions', label: 'Response Actions', icon: Zap, scope: 'org', section: 'org' },
  { to: '/approvals', label: 'Approval Queue', icon: ClipboardCheck, scope: 'org', section: 'org' },
  { to: '/blocklist', label: 'Block List', icon: Ban, scope: 'org', section: 'org' },
  { to: '/action-log', label: 'Action Log', icon: ScrollText, scope: 'org', section: 'org' },
  { to: '/policies', label: 'Policy Management', icon: Settings2, scope: 'org', section: 'org', adminOnly: true },
  // --- system ---
  { to: '/dlq', label: 'Dead Letter Queue', icon: Zap, scope: 'both', section: 'system', adminOnly: true },
  { to: '/reports', label: 'Reports', icon: FileBarChart, scope: 'org', section: 'system' },
  { to: '/settings', label: 'Settings', icon: Settings, scope: 'both', section: 'system' },
];

/** Routes that org-only in the *analyze* group (guarded, not hidden). */
export const ORG_ONLY_ROUTES = NAV_ITEMS.filter((i) => i.scope === 'org').map((i) => i.to);

export interface NavWorkspace {
  /** True when an organization workspace is active (orgEnabled + non-personal org). */
  isOrg: boolean;
  /** Permission check from the auth store (`can('admin')` etc.). */
  can: (permission: 'analyze' | 'mutate' | 'admin') => boolean;
}

export interface NavSectionView {
  section: NavSection;
  label: string;
  items: NavItem[];
}

const SECTION_LABELS: Record<NavSection, string> = {
  analyze: 'Analyze',
  mailbox: 'Email Security',
  history: 'History & Audit',
  org: 'Organization',
  system: 'System',
};

/**
 * Resolve the visible nav sections for the active workspace.
 * Personal mode: only `scope: 'user' | 'both'` items; org-side modules are
 * excluded (and route-guarded). Org mode: everything, with adminOnly gates.
 */
export function getNavSections(workspace: NavWorkspace): NavSectionView[] {
  const visible = NAV_ITEMS.filter((item) => {
    if (item.scope === 'org' && !workspace.isOrg) return false;
    if (item.adminOnly && !workspace.can('admin')) return false;
    return true;
  });

  const order: NavSection[] = ['analyze', 'mailbox', 'history', 'org', 'system'];
  return order
    .map((section) => ({
      section,
      label: SECTION_LABELS[section],
      items: visible.filter((item) => item.section === section),
    }))
    .filter((s) => s.items.length > 0);
}

/** True when `path` is an org-scope route (used by the route guard). */
export function isOrgScopeRoute(path: string): boolean {
  return ORG_ONLY_ROUTES.includes(path);
}
