import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Bot, ChevronsLeft, ChevronsRight, Shield } from 'lucide-react';
import { useUiStore } from '../../store/uiStore';
import { useAuthStore } from '../../store/authStore';
import * as api from '../../services/api';
import { getNavSections, type NavItem } from '../../nav';
import { useRealtimeEmailStore } from '../../hooks/useRealtimeEmails';

function linkClass(isActive: boolean, collapsed: boolean) {
  return `flex items-center gap-3 border-l-2 py-2 pr-3 text-sm transition ${
    collapsed ? 'justify-center pl-0' : 'pl-4'
  } ${
    isActive
      ? 'border-red-600 bg-zinc-900 text-red-400 font-semibold'
      : 'border-transparent text-zinc-400 hover:bg-zinc-900/50 hover:text-zinc-100'
  }`;
}

export default function Sidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const setAssistantOpen = useUiStore((s) => s.setAssistantOpen);
  const can = useAuthStore((s) => s.can);
  const isOrgWorkspace = false;
  const isAdmin = can('admin');
  const liveEmailCount = useRealtimeEmailStore((s) => s.liveCount);

  // Pending-approval badge for the ORGANIZATION section (polled every 60s)
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  useEffect(() => {
    if (!isOrgWorkspace) return;
    let cancelled = false;
    const fetchPending = () =>
      api
        .listActions({ status: 'pending', page_size: 1 })
        .then((res) => {
          if (!cancelled) setPendingCount(res.total);
        })
        .catch(() => undefined);
    fetchPending();
    const interval = setInterval(fetchPending, 60_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [isOrgWorkspace]);

  const renderItems = (items: NavItem[]) =>
    items.map(({ to, label, icon: Icon, adminOnly }) => {
      if (adminOnly && !isAdmin) return null;
      return (
        <NavLink
          key={to}
          to={to}
          title={collapsed ? label : undefined}
          className={({ isActive }) => linkClass(isActive, collapsed)}
        >
          <Icon className="h-4 w-4 shrink-0" />
          {!collapsed && <span className="truncate">{label}</span>}
          {!collapsed && to === '/approvals' && pendingCount !== null && pendingCount > 0 && (
            <span className="ml-auto rounded-full bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white">
              {pendingCount}
            </span>
          )}
          {!collapsed && to === '/quarantine' && liveEmailCount > 0 && (
            <span className="ml-auto rounded-full bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white animate-pulse">
              {liveEmailCount}
            </span>
          )}
        </NavLink>
      );
    });

  return (
    <aside
      className={`flex h-full flex-col border-r border-zinc-800 bg-zinc-950 backdrop-blur transition-all duration-200 ${
        collapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 border-b border-zinc-800 px-4 py-4">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-red-500/10 ring-1 ring-red-500/40">
          <Shield className="h-5 w-5 text-red-400" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <div className="truncate font-mono text-sm font-bold tracking-widest text-red-400">CYBERGUARD</div>
            <div className="truncate text-[10px] uppercase tracking-wider text-zinc-500">SOC Command Center</div>
          </div>
        )}
      </div>

      {/* Navigation — workspace-scoped via src/nav.ts (single source of truth) */}
      <nav className="flex-1 overflow-y-auto py-3">
        {getNavSections({ isOrg: isOrgWorkspace, can }).map((section, idx) => (
          <div key={section.section}>
            <div className={`mt-3 border-t border-zinc-800/80 pt-3 ${collapsed ? '' : 'px-4'} ${idx === 0 ? 'mt-0 border-t-0' : ''}`}>
              {!collapsed && (
                <p className="text-[10px] font-bold uppercase tracking-widest text-zinc-600">{section.label}</p>
              )}
            </div>
            {renderItems(section.items)}
          </div>
        ))}
      </nav>

      {/* Bottom section */}
      <div className="border-t border-zinc-800 p-3 space-y-2">
        <button
          onClick={() => setAssistantOpen(true)}
          className={`flex w-full items-center gap-3 rounded-lg bg-red-500/10 px-3 py-2.5 text-sm font-medium text-red-400 ring-1 ring-red-500/30 hover:bg-red-500/20 transition ${
            collapsed ? 'justify-center' : ''
          }`}
        >
          <Bot className="h-4 w-4 shrink-0" />
          {!collapsed && <span>SOC Assistant</span>}
        </button>
        <button
          onClick={() => useUiStore.getState().toggleSidebar()}
          className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-xs text-zinc-500 hover:bg-zinc-900/60 hover:text-zinc-300 transition ${
            collapsed ? 'justify-center' : ''
          }`}
        >
          {collapsed ? <ChevronsRight className="h-4 w-4" /> : <ChevronsLeft className="h-4 w-4" />}
          {!collapsed && <span>Collapse Sidebar</span>}
        </button>
      </div>
    </aside>
  );
}
