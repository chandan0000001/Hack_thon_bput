export type Severity = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type ThreatModule =
  | 'phishing'
  | 'url'
  | 'impersonation'
  | 'deepfake'
  | 'account_takeover'
  | 'network'
  | 'api_abuse';
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'closed';
export type EventStatus = 'received' | 'analyzing' | 'completed' | 'failed';

export type OrganizationRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  name: string;
  email: string;
  role: OrganizationRole;
  avatar?: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  is_personal: boolean;
  role: OrganizationRole;
  owner_id?: string;
  created_at?: string;
}

export interface UserContext {
  id: string;
  email: string;
  full_name: string;
  is_single_user: boolean;
  active_role: OrganizationRole;
  active_organization: {
    id: string;
    name: string;
    is_personal: boolean;
    role: OrganizationRole;
  };
  personal_organization_id: string | null;
  organizations: Organization[];
}

export interface Indicator {
  id: string;
  type: string;
  value: string;
  severity: Severity;
  description: string;
  /** Where the signal came from — e.g. 'attachment' from the ATTACH-SCAN pipeline. */
  source?: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface RecommendedAction {
  id: string;
  action: string;
  description: string;
  automationLevel: 'automatic' | 'semi-automatic' | 'manual';
  requiresApproval: boolean;
  priority: 'low' | 'medium' | 'high' | 'critical';
  executed?: boolean;
  executedAt?: string;
}

export interface AnalysisResult {
  eventId: string;
  module: ThreatModule;
  threatType: string;
  riskScore: number;
  severity: Severity;
  confidence: number;
  indicators: Indicator[];
  explanation: string;
  recommendedActions: RecommendedAction[];
  mitreTechniques: MitreTechnique[];
  timestamp: string;
  status: EventStatus;
  // AUTH-VERIFY: non-fatal analysis caveats (e.g. auth not verifiable without headers)
  warnings?: string[];
  // AUTH-VERIFY: per-protocol verification statuses (spf/dkim/dmarc)
  authVerification?: AuthVerification;
  // Optional extras produced by specific detectors
  authenticityScore?: number;
  manipulationProbability?: number;
  lexicalFeatures?: { feature: string; value: string; riskContribution: number }[];
  // Media forensics extras (deepfake module)
  method?: string;
  simulated?: boolean;
}

export interface AuthVerification {
  source?: string;
  risk_score?: number;
  spf?: string;
  dkim?: string;
  dmarc?: string;
}

export interface Alert {
  id: string;
  title: string;
  module: ThreatModule;
  severity: Severity;
  riskScore: number;
  status: 'new' | 'acknowledged' | 'resolved' | 'dismissed';
  summary: string;
  indicators: Indicator[];
  explanation: string;
  recommendedActions: RecommendedAction[];
  mitreTechniques: MitreTechnique[];
  // AUTH-VERIFY: non-fatal analysis caveats carried by AlertResponse
  warnings?: string[];
  targetUser?: string;
  targetService?: string;
  sourceIp?: string;
  timestamp: string;
}

export interface IncidentEvent {
  id: string;
  action: string;
  actor: string;
  timestamp: string;
  details: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  assignedTo?: string;
  linkedAlertIds: string[];
  timeline: IncidentEvent[];
  createdAt: string;
  updatedAt: string;
}

export interface LoginEvent {
  id: string;
  userId: string;
  username: string;
  sourceIp: string;
  location: string;
  device: string;
  status: 'success' | 'failed';
  riskScore: number;
  timestamp: string;
  anomalies: string[];
}

export interface NetworkFlow {
  id: string;
  sourceIp: string;
  destIp: string;
  destDomain: string;
  port: number;
  protocol: string;
  bytesOut: number;
  bytesIn: number;
  anomalyScore: number;
  flags: string[];
  timestamp: string;
}

export interface ApiLogEntry {
  id: string;
  endpoint: string;
  method: string;
  sourceIp: string;
  userAgent: string;
  statusCode: number;
  responseTime: number;
  anomalyScore: number;
  flags: string[];
  timestamp: string;
}

export interface AuditLog {
  id: string;
  userId: string;
  userName: string;
  action: string;
  resource: string;
  details: string;
  timestamp: string;
  actor_type?: 'user' | 'system' | 'scheduler';
}

export interface DashboardSummary {
  totalEventsAnalyzed: number;
  threatsDetected: number;
  phishingAttempts: number;
  impersonationAttempts: number;
  suspectedDeepfakes: number;
  accountTakeoverAttempts: number;
  riskDistribution: { name: string; value: number; color: string }[];
  threatCategories: { name: string; count: number }[];
  attackTimeline: { hour: string; threats: number; events: number }[];
  topTargetedUsers: { user: string; attacks: number; lastAttack: string }[];
  topTargetedServices: { service: string; attacks: number; riskLevel: Severity }[];
  recentAlerts: Alert[];
  incidentSummary: { open: number; investigating: number; contained: number; closed: number };
}

export interface ResponseActionCatalog {
  id: string;
  action: string;
  targetType: string;
  automationLevel: 'automatic' | 'semi-automatic' | 'manual';
  requiresApproval: boolean;
  description: string;
}

export interface ResponseExecution {
  id: string;
  actionId: string;
  actionName: string;
  target: string;
  status: 'pending' | 'approved' | 'executed' | 'rejected';
  executedBy: string;
  approvedBy?: string;
  timestamp: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
}

export interface OrganizationMember {
  id: string;
  organizationId: string;
  userId: string;
  email?: string | null;
  fullName?: string | null;
  role: OrganizationRole;
  joinedAt: string;
}


// ---------------------------------------------------------------------------
// Dual-Mode Enforcement (Phases 1-3)
// ---------------------------------------------------------------------------

export type ActionExecutionStatus =
  | 'pending'
  | 'approved'
  | 'executing'
  | 'success'
  | 'failed'
  | 'rejected'
  | 'skipped'
  | 'released'
  | 'unblocked';

export interface ActionExecution {
  id: string;
  organization_id: string | null;
  alert_id: string | null;
  event_id: string | null;
  action_type: string;
  target: Record<string, unknown>;
  status: ActionExecutionStatus;
  execution_mode: 'client' | 'server';
  triggered_by: string;
  triggered_by_id?: string | null;
  requires_approval: boolean;
  approved_by: string | null;
  approved_at: string | null;
  rejection_reason: string | null;
  executed_at: string | null;
  execution_result: Record<string, unknown> | null;
  risk_score: number;
  severity: Exclude<Severity, 'safe'>;
  threat_type: string;
  module: string;
  policy_id: string | null;
  created_at: string;
}

export interface ActionListResponse {
  total: number;
  page: number;
  page_size: number;
  items: ActionExecution[];
}

export interface EnforcementPolicy {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  is_active: boolean;
  phishing_high_threshold: number;
  phishing_medium_threshold: number;
  deepfake_high_threshold: number;
  deepfake_medium_threshold: number;
  ato_high_threshold: number;
  ato_medium_threshold: number;
  network_high_threshold: number;
  network_medium_threshold: number;
  impersonation_high_threshold: number;
  impersonation_medium_threshold: number;
  action_on_critical: string;
  action_on_high: string;
  action_on_medium: string;
  action_on_low: string;
  auto_execute_critical: boolean;
  auto_execute_high: boolean;
  auto_execute_medium: boolean;
  auto_execute_low: boolean;
  notify_soc_on_critical: boolean;
  notify_soc_on_high: boolean;
  notify_user_on_medium: boolean;
  created_at: string;
  updated_at: string;
}

export interface PolicyListResponse {
  policies: EnforcementPolicy[];
  active_policy_id: string | null;
}

export interface PolicyUpdatePayload {
  name?: string;
  description?: string;
  is_active?: boolean;
  phishing_high_threshold?: number;
  phishing_medium_threshold?: number;
  deepfake_high_threshold?: number;
  deepfake_medium_threshold?: number;
  ato_high_threshold?: number;
  ato_medium_threshold?: number;
  network_high_threshold?: number;
  network_medium_threshold?: number;
  impersonation_high_threshold?: number;
  impersonation_medium_threshold?: number;
  action_on_critical?: string;
  action_on_high?: string;
  action_on_medium?: string;
  action_on_low?: string;
  auto_execute_critical?: boolean;
  auto_execute_high?: boolean;
  auto_execute_medium?: boolean;
  auto_execute_low?: boolean;
  notify_soc_on_critical?: boolean;
  notify_soc_on_high?: boolean;
  notify_user_on_medium?: boolean;
}

// --- Email Connectors (Phase 1-2: Gmail only) ---

export type ConnectorProvider = 'gmail' | 'outlook' | 'yahoo' | 'icloud';
export type ConnectorStatus = 'connected' | 'reauth_required' | 'revoked' | 'error';
export type ConnectorProviderStatus = 'enabled' | 'coming_soon' | 'unsupported';

export interface EmailProviderCapability {
  read_messages: boolean;
  read_attachments: boolean;
  modify_labels: boolean;
  quarantine: boolean;
  trash: boolean;
  permanent_delete: boolean;
  sender_rules: boolean;
  send_mail: boolean;
  unsupported_reason?: string | null;
}

export interface EmailProviderRegistryEntry {
  provider: ConnectorProvider;
  display_name: string;
  status: ConnectorProviderStatus;
  capabilities: EmailProviderCapability | null;
  detail: string;
}

export interface EmailConnectorAccount {
  id: string;
  provider: ConnectorProvider;
  provider_email: string;
  status: ConnectorStatus;
  scopes: string[];
  capabilities: Partial<EmailProviderCapability>;
  last_test_at: string | null;
  last_sync_at: string | null;
  last_error: string | null;
  created_at: string | null;
}

export interface ConnectorOperationLog {
  id: string;
  connector_id: string | null;
  provider: ConnectorProvider;
  operation: 'authorize' | 'callback' | 'token_refresh' | 'test_connection' | 'disconnect';
  status: 'success' | 'failed' | 'unsupported' | 'insufficient_scope' | 'reauth_required';
  message: string | null;
  provider_error_code: string | null;
  created_at: string | null;
}

// --- Mailbox scanning (Phase 3) ---

export interface NormalizedMessage {
  provider_message_id: string;
  provider: string;
  sender: string;
  recipients: string[];
  subject: string;
  body_text: string | null;
  body_html: string | null;
  headers: Record<string, string>;
  attachments_meta: { filename: string; mime_type?: string; size?: number; is_media?: boolean }[];
  received_at: string | null;
  is_read: boolean;
}

export interface MailMessageSummary {
  provider_message_id: string;
  provider: string;
  sender: string;
  recipients: string[];
  subject: string;
  received_at: string | null;
  is_read: boolean;
  has_attachments: boolean;
  body_preview: string;
}

export interface ScanIndicator {
  name: string;
  value: string;
  weight: number;
}

export interface FeatureAnalysis {
  engine: string;
  severity: string;
  score: number;
  explanation: string;
  indicators: ScanIndicator[];
}

export interface ScanResult {
  message_id: string;
  provider: string;
  sender: string;
  subject: string;
  received_at: string | null;
  overall_severity: string;
  overall_score: number;
  overall_explanation: string;
  feature_analyses: FeatureAnalysis[];
  recommended_action: string;
  provider_operation_status: string;
  provider_operation_detail: string | null;
}

export interface MessageAnalysis {
  scan: ScanResult;
  message: NormalizedMessage;
}

// --- Enforcement (Phase 4) ---

export interface ConnectorSettings {
  connector_id: string;
  quarantine_expiry_hours: number | null;
  permanent_delete_enabled: boolean;
  auto_quarantine_enabled: boolean;
  updated_at: string | null;
}

export interface QuarantinedItem {
  id: string;
  connector_id: string;
  provider_message_id: string;
  sender_email: string;
  reason: string;
  severity: string;
  scan_result: ScanResult;
  quarantined_at: string | null;
  expires_at: string | null;
  status: string;
  last_error: string | null;
}

export interface BlockedSender {
  id: string;
  connector_id: string;
  sender_email: string;
  provider_rule_id: string | null;
  reason: string;
  blocked_at: string | null;
  expires_at: string | null;
  status: string;
  last_error: string | null;
}

// --- Trusted senders (FP-hardening, Deliverable 1) ---

export interface TrustedSender {
  id: string;
  sender_email: string;
  sender_domain: string | null;
  reason: string;
  created_at: string | null;
}

export interface ReleaseAndTrustResult {
  id: string;
  status: string;
  provider_operation_status: string;
  message?: string | null;
  trusted: boolean;
  // Present when the sender still has an active provider filter — the UI must
  // offer "also unblock" as an explicit second action (never implicit).
  existing_block: BlockedSender | null;
}

// --- Security history (Phase 5) ---

export type SecurityEventType =
  | 'scan_verdict' | 'quarantine' | 'release' | 'keep' | 'delete'
  | 'sender_block' | 'sender_release' | 'sender_expiry'
  | 'connector_connect' | 'connector_disconnect' | 'connector_test';
export type SecurityActorType = 'user' | 'system' | 'scheduler';

export interface SecurityEventRecord {
  id: string;
  event_type: string;
  connector_id: string | null;
  provider: string | null;
  provider_message_id: string | null;
  sender_email: string | null;
  subject: string | null;
  severity: string | null;
  score: number | null;
  explanation: string | null;
  indicators: { name: string; value: string; weight: number }[];
  action_requested: string | null;
  action_performed: string | null;
  actor_type: SecurityActorType;
  operation_status: string | null;
  operation_detail: string | null;
  quarantined_item_id: string | null;
  blocked_sender_id: string | null;
  created_at: string | null;
}

export interface ReviewAvailableActions {
  release: boolean;
  keep: boolean;
  delete: boolean;
  delete_mode: 'trash' | 'permanent' | null;
  connector_ready: boolean;
}

export interface QuarantineReview {
  item: {
    id: string;
    connector_id: string;
    provider_message_id: string;
    sender_email: string;
    reason: string;
    severity: string;
    status: string;
    quarantined_at: string | null;
    expires_at: string | null;
    last_error: string | null;
  };
  message: {
    provider_message_id: string | null;
    provider: string | null;
    sender_email: string | null;
    subject: string | null;
    body_preview: string | null;
    received_at: string | null;
  };
  scan_result: ScanResult | null;
  event_chain: SecurityEventRecord[];
  available_actions: ReviewAvailableActions;
}

// --- Event email notifications (Phase 7) ---

export interface NotificationLogEntry {
  id: string;
  event_type: string;
  recipient_email: string;
  subject: string;
  status: 'sent' | 'failed';
  backend: 'db_log' | 'smtp';
  error_detail: string | null;
  created_at: string | null;
}

// --- Dead Letter Queue (RT-10) ---

export interface DlqJobRetryHistoryItem {
  attempt: number;
  error: string;
  timestamp: string;
}

export interface DlqJob {
  job_id: string;
  job_type: string;
  owner_user_id: string;
  payload: Record<string, any>;
  error: string | null;
  retry_count: number;
  next_retry_at?: string | null;
  created_at: string;
  updated_at: string;
  retry_history?: DlqJobRetryHistoryItem[];
}

export interface DlqJobsResponse {
  jobs: DlqJob[];
  total: number;
  limit: number;
  offset: number;
}

export interface DlqStats {
  total_dead_letter: number;
  by_job_type: Record<string, number>;
  oldest_age_hours: number;
}
