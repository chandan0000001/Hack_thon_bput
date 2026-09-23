import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
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

/**
 * Workspace guard: pass-through for personal workspace.
 */
function WorkspaceGuard({ children }: { path?: string; children: React.ReactNode }) {
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

          {/* Org UI teardown: catch-all redirects for old org paths → /dashboard */}
          <Route path="/org" element={<Navigate to="/dashboard" replace />} />
          <Route path="/org/*" element={<Navigate to="/dashboard" replace />} />
          <Route path="/organization" element={<Navigate to="/dashboard" replace />} />

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
