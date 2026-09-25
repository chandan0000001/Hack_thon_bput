import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import MainLayout from './components/layout/MainLayout';
import ProtectedRoute from './components/layout/ProtectedRoute';
import RoleGuard from './components/layout/RoleGuard';
import Landing from './pages/Landing';
import Login from './pages/Login';
import ResetPassword from './pages/ResetPassword';
import EmailConnectors from './pages/EmailConnectors';
import BlockedSenders from './pages/BlockedSenders';
import SecurityHistory from './pages/SecurityHistory';
import NotificationLog from './pages/NotificationLog';
import Dashboard from './pages/Dashboard';
import ApprovalQueue from './pages/ApprovalQueue';
import QuarantineQueue from './pages/QuarantineQueue';
import BlockList from './pages/BlockList';
import ActionLog from './pages/ActionLog';
import PolicyManagement from './pages/PolicyManagement';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import ResponseActions from './pages/ResponseActions';
import AuditLogs from './pages/AuditLogs';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import DLQDashboard from './pages/DLQDashboard';

// Personal workspace modules
import PhishingAnalysis from './pages/PhishingAnalysis';
import UrlAnalysis from './pages/UrlAnalysis';
import ImpersonationAnalysis from './pages/ImpersonationAnalysis';
import DeepfakeAnalysis from './pages/DeepfakeAnalysis';
import LogAnalysis from './pages/LogAnalysis';
import AccountTakeover from './pages/AccountTakeover';
import NetworkThreats from './pages/NetworkThreats';

// Org window modules
import OrgSelector from './pages/OrgSelector';
import ProjectSelector from './pages/ProjectSelector';
import OrgWorkspaceShell from './pages/OrgWorkspaceShell';
import { useAuthStore } from './store/authStore';

/**
 * Workspace guard: pass-through for personal workspace.
 */
function WorkspaceGuard({ children }: { path?: string; children: React.ReactNode }) {
  return <>{children}</>;
}

/**
 * Org route guard: redirects unauthenticated users to /login?mode=org.
 */
function OrgGuard({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const hydrated = useAuthStore((s) => s.hydrated);

  if (!hydrated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950">
        <Loader2 className="h-6 w-6 animate-spin text-red-500" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login?mode=org" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* Org window routes */}
        <Route path="/org/entry" element={<Navigate to="/login?mode=org" replace />} />
        <Route
          path="/org/select"
          element={
            <OrgGuard>
              <OrgSelector />
            </OrgGuard>
          }
        />
        <Route
          path="/org/:orgId/projects"
          element={
            <OrgGuard>
              <ProjectSelector />
            </OrgGuard>
          }
        />
        {/* ORG-SHELL-1: empty workspace shell after project selection */}
        <Route
          path="/org/:orgId/projects/:projectId/workspace"
          element={
            <OrgGuard>
              <OrgWorkspaceShell />
            </OrgGuard>
          }
        />

        {/* Org redirects for root / legacy URLs */}
        <Route path="/org" element={<Navigate to="/org/select" replace />} />
        <Route path="/organization" element={<Navigate to="/org/select" replace />} />
        <Route path="/org/*" element={<Navigate to="/dashboard" replace />} />

        {/* Personal workspace protected routes */}
        <Route
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        >
          {/* Analyze / Personal workspace */}
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/phishing" element={<PhishingAnalysis />} />
          <Route path="/url-analysis" element={<UrlAnalysis />} />
          <Route path="/impersonation" element={<ImpersonationAnalysis />} />
          <Route path="/deepfake" element={<DeepfakeAnalysis />} />
          <Route path="/log-analysis" element={<LogAnalysis />} />
          <Route
            path="/account-takeover"
            element={
              <WorkspaceGuard path="/account-takeover">
                <AccountTakeover />
              </WorkspaceGuard>
            }
          />
          <Route
            path="/network-threats"
            element={
              <WorkspaceGuard path="/network-threats">
                <NetworkThreats />
              </WorkspaceGuard>
            }
          />

          {/* Mailbox */}
          <Route path="/email-connectors" element={<EmailConnectors />} />
          <Route path="/quarantine" element={<QuarantineQueue />} />
          <Route path="/blocked-senders" element={<BlockedSenders />} />

          {/* History */}
          <Route path="/security-history" element={<SecurityHistory />} />
          <Route path="/notification-log" element={<NotificationLog />} />
          <Route
            path="/audit-logs"
            element={
              <WorkspaceGuard path="/audit-logs">
                <AuditLogs />
              </WorkspaceGuard>
            }
          />

          {/* Org modules */}
          <Route
            path="/alerts"
            element={
              <WorkspaceGuard path="/alerts">
                <Alerts />
              </WorkspaceGuard>
            }
          />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route
            path="/incidents"
            element={
              <WorkspaceGuard path="/incidents">
                <Incidents />
              </WorkspaceGuard>
            }
          />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route
            path="/response-actions"
            element={
              <WorkspaceGuard path="/response-actions">
                <ResponseActions />
              </WorkspaceGuard>
            }
          />
          <Route
            path="/approvals"
            element={
              <WorkspaceGuard path="/approvals">
                <ApprovalQueue />
              </WorkspaceGuard>
            }
          />
          <Route
            path="/blocklist"
            element={
              <WorkspaceGuard path="/blocklist">
                <BlockList />
              </WorkspaceGuard>
            }
          />
          <Route
            path="/action-log"
            element={
              <WorkspaceGuard path="/action-log">
                <ActionLog />
              </WorkspaceGuard>
            }
          />
          <Route
            path="/policies"
            element={
              <WorkspaceGuard path="/policies">
                <RoleGuard minimumRole="admin">
                  <PolicyManagement />
                </RoleGuard>
              </WorkspaceGuard>
            }
          />

          {/* System */}
          <Route
            path="/dlq"
            element={
              <RoleGuard minimumRole="admin">
                <DLQDashboard />
              </RoleGuard>
            }
          />
          <Route
            path="/reports"
            element={
              <WorkspaceGuard path="/reports">
                <Reports />
              </WorkspaceGuard>
            }
          />
          <Route path="/settings" element={<Settings />} />
        </Route>
        <Route path="/" element={<Landing />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
