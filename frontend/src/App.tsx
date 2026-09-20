import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import ProtectedRoute from './components/layout/ProtectedRoute';
import RoleGuard from './components/layout/RoleGuard';
import Landing from './pages/Landing';
import Login from './pages/Login';
import ResetPassword from './pages/ResetPassword';
import OrganizationManagement from './pages/OrganizationManagement';
import OrganizationCreate from './pages/OrganizationCreate';
import OrganizationSettings from './pages/OrganizationSettings';
import OrganizationDashboard from './pages/OrganizationDashboard';
import OrgFeatureDashboard from './pages/OrgFeatureDashboard';
import OrgLogAnalysis from './pages/OrgLogAnalysis';
import OrgAccountTakeover from './pages/OrgAccountTakeover';
import OrgMailServers from './pages/OrgMailServers';
import OrgMailServerLogs from './pages/OrgMailServerLogs';
import OrgMailServerSettings from './pages/OrgMailServerSettings';
import OrgNotifications from './pages/OrgNotifications';
import OrgNotificationLog from './pages/OrgNotificationLog';
import Docs from './pages/Docs';
import ComingSoon from './pages/ComingSoon';
import EmailConnectors from './pages/EmailConnectors';
import BlockedSenders from './pages/BlockedSenders';
import SecurityHistory from './pages/SecurityHistory';
import NotificationLog from './pages/NotificationLog';
import LogAnalysis from './pages/LogAnalysis';
import { isOrgScopeRoute } from './nav';
import { useAuthStore } from './store/authStore';
import Dashboard from './pages/Dashboard';
import ApprovalQueue from './pages/ApprovalQueue';
import QuarantineQueue from './pages/QuarantineQueue';
import BlockList from './pages/BlockList';
import ActionLog from './pages/ActionLog';
import PolicyManagement from './pages/PolicyManagement';
import PhishingAnalysis from './pages/PhishingAnalysis';
import UrlAnalysis from './pages/UrlAnalysis';
import ImpersonationAnalysis from './pages/ImpersonationAnalysis';
import DeepfakeAnalysis from './pages/DeepfakeAnalysis';
import AccountTakeover from './pages/AccountTakeover';
import NetworkThreats from './pages/NetworkThreats';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import ResponseActions from './pages/ResponseActions';
import AuditLogs from './pages/AuditLogs';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import DLQDashboard from './pages/DLQDashboard';

/**
 * Organization features are frozen server-side (ORG_ENABLED=false). While the
 * flag is off, org routes render the ComingSoon placeholder instead of the
 * real pages; they reactivate automatically once the backend flips the flag.
 */
function OrgFeature({ children }: { children: React.ReactNode }) {
  const orgEnabled = useAuthStore((s) => s.orgEnabled);
  if (!orgEnabled) return <ComingSoon />;
  return <>{children}</>;
}

/**
 * Workspace-scoped route guard (Excalidraw step-1): org-scope routes render
 * the ComingSoon placeholder in personal workspaces — no redirect loops.
 * Scope comes from src/nav.ts (single source of truth).
 */
function WorkspaceGuard({ path, children }: { path: string; children: React.ReactNode }) {
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const orgEnabled = useAuthStore((s) => s.orgEnabled);
  const isOrg = Boolean(orgEnabled && activeOrganization && !activeOrganization.is_personal);
  if (isOrgScopeRoute(path) && !isOrg) {
    return <ComingSoon message="This module is part of the Organization workspace." />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        >
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/email-connectors" element={<EmailConnectors />} />
          <Route path="/blocked-senders" element={<BlockedSenders />} />
          <Route path="/security-history" element={<SecurityHistory />} />
          <Route path="/log-analysis" element={<LogAnalysis />} />
          <Route path="/notification-log" element={<NotificationLog />} />
          <Route path="/approvals" element={<WorkspaceGuard path="/approvals"><ApprovalQueue /></WorkspaceGuard>} />
          <Route path="/quarantine" element={<QuarantineQueue />} />
          <Route path="/blocklist" element={<WorkspaceGuard path="/blocklist"><BlockList /></WorkspaceGuard>} />
          <Route path="/action-log" element={<WorkspaceGuard path="/action-log"><ActionLog /></WorkspaceGuard>} />
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
          <Route
            path="/organization"
            element={
              <WorkspaceGuard path="/organization">
              <OrgFeature>
                <OrganizationManagement />
              </OrgFeature>
              </WorkspaceGuard>
            }
          />
          <Route path="/phishing" element={<PhishingAnalysis />} />
          <Route path="/url-analysis" element={<UrlAnalysis />} />
          <Route path="/impersonation" element={<ImpersonationAnalysis />} />
          <Route path="/deepfake" element={<DeepfakeAnalysis />} />
          <Route path="/account-takeover" element={<WorkspaceGuard path="/account-takeover"><AccountTakeover /></WorkspaceGuard>} />
          <Route path="/network-threats" element={<WorkspaceGuard path="/network-threats"><NetworkThreats /></WorkspaceGuard>} />
          <Route path="/alerts" element={<WorkspaceGuard path="/alerts"><Alerts /></WorkspaceGuard>} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/incidents" element={<WorkspaceGuard path="/incidents"><Incidents /></WorkspaceGuard>} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/response-actions" element={<WorkspaceGuard path="/response-actions"><ResponseActions /></WorkspaceGuard>} />
          <Route path="/audit-logs" element={<WorkspaceGuard path="/audit-logs"><AuditLogs /></WorkspaceGuard>} />
          <Route path="/reports" element={<WorkspaceGuard path="/reports"><Reports /></WorkspaceGuard>} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/docs" element={<Docs />} />
          <Route
            path="/dlq"
            element={
              <RoleGuard minimumRole="admin">
                <DLQDashboard />
              </RoleGuard>
            }
          />
          {/* ORG-1 foundation: always-on org endpoints (backend /orgs router) */}
          <Route path="/org/create" element={<OrganizationCreate />} />
          <Route path="/org/:orgId/settings" element={<OrganizationSettings />} />
          {/* ORG-2: dashboards + Splunk-style live log analysis */}
          <Route path="/org/:orgId/dashboard" element={<OrganizationDashboard />} />
          <Route path="/org/:orgId/dashboard/:feature" element={<OrgFeatureDashboard />} />
          <Route path="/org/:orgId/logs" element={<OrgLogAnalysis />} />
          <Route path="/org/:orgId/account-takeover" element={<OrgAccountTakeover />} />
          {/* ORG-3: server-to-server mail connectors */}
          <Route path="/org/:orgId/mail-servers" element={<OrgMailServers />} />
          <Route path="/org/:orgId/mail-servers/:serverId/logs" element={<OrgMailServerLogs />} />
          <Route path="/org/:orgId/mail-servers/:serverId/settings" element={<OrgMailServerSettings />} />
          {/* ORG-4: email notification groups */}
          <Route path="/org/:orgId/notifications" element={<OrgNotifications />} />
          <Route path="/org/:orgId/notifications/logs" element={<OrgNotificationLog />} />
        </Route>
        <Route path="/" element={<Landing />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
