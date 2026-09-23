import { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import {
  Ban,
  Check,
  Copy,
  FolderOpen,
  Key,
  Lock,
  Plus,
  Save,
  Trash2,
  UserPlus,
  Users,
  AlertTriangle,
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { useUiStore } from '../store/uiStore';
import {
  orgApi,
  type OrgProject,
  type OrgApiKey,
  type OrgApiKeyCreated,
  type OrgBlockedIndicator,
  type OrgMember,
} from '../services/orgApi';

export default function OrgProjectSettings() {
  const { orgId: paramOrgId, projectId: paramProjectId } = useParams();
  const addToast = useUiStore((s) => s.addToast);
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const activeProject = useAuthStore((s) => s.activeProject);

  const orgId = paramOrgId || activeOrganization?.id || '';
  const projectId = paramProjectId || activeProject?.id || '';

  const [activeTab, setActiveTab] = useState<
    'general' | 'keys' | 'indicators' | 'members' | 'access'
  >('general');

  // General tab state
  const [project, setProject] = useState<OrgProject | null>(null);
  const [projectName, setProjectName] = useState<string>('');
  const [savingGeneral, setSavingGeneral] = useState<boolean>(false);

  // API Keys tab state
  const [apiKeys, setApiKeys] = useState<OrgApiKey[]>([]);
  const [keysLoading, setKeysLoading] = useState<boolean>(false);
  const [createdKey, setCreatedKey] = useState<OrgApiKeyCreated | null>(null);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [confirmedSaved, setConfirmedSaved] = useState<boolean>(false);

  // Blocked Indicators tab state
  const [indicators, setIndicators] = useState<OrgBlockedIndicator[]>([]);
  const [indicatorType, setIndicatorType] = useState<'ip' | 'domain' | 'email' | 'hash' | 'actor'>('ip');
  const [indicatorValue, setIndicatorValue] = useState<string>('');
  const [indicatorReason, setIndicatorReason] = useState<string>('');
  const [showAddIndicator, setShowAddIndicator] = useState<boolean>(false);

  // Members tab state
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [inviteEmail, setInviteEmail] = useState<string>('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'analyst' | 'viewer'>('analyst');
  const [showInviteModal, setShowInviteModal] = useState<boolean>(false);

  // Load project details
  const loadProject = useCallback(async () => {
    if (!orgId || !projectId) return;
    try {
      const p = await orgApi.getProject(orgId, projectId);
      setProject(p);
      setProjectName(p.name);
    } catch (err: any) {
      addToast(err?.message || 'Failed to load project details', 'high');
    }
  }, [orgId, projectId, addToast]);

  // Load API keys
  const loadKeys = useCallback(async () => {
    if (!orgId || !projectId) return;
    setKeysLoading(true);
    try {
      const keys = await orgApi.listProjectApiKeys(orgId, projectId);
      setApiKeys(keys);
    } catch (err: any) {
      addToast(err?.message || 'Failed to load API keys', 'high');
    } finally {
      setKeysLoading(false);
    }
  }, [orgId, projectId, addToast]);

  // Load Blocked Indicators
  const loadIndicators = useCallback(async () => {
    if (!orgId) return;
    try {
      const list = await orgApi.listBlockedIndicators(orgId);
      setIndicators(list);
    } catch (err: any) {
      addToast(err?.message || 'Failed to load indicators', 'high');
    }
  }, [orgId, addToast]);

  // Load Members
  const loadMembers = useCallback(async () => {
    if (!orgId) return;
    try {
      const list = await orgApi.listMembers(orgId);
      setMembers(list);
    } catch (err: any) {
      addToast(err?.message || 'Failed to load members', 'high');
    }
  }, [orgId, addToast]);

  useEffect(() => {
    void loadProject();
  }, [loadProject]);

  useEffect(() => {
    if (activeTab === 'keys') void loadKeys();
    if (activeTab === 'indicators') void loadIndicators();
    if (activeTab === 'members') void loadMembers();
  }, [activeTab, loadKeys, loadIndicators, loadMembers]);

  // General tab actions
  const handleSaveGeneral = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !projectId || !projectName.trim()) return;
    setSavingGeneral(true);
    try {
      const updated = await orgApi.updateProject(orgId, projectId, { name: projectName.trim() });
      setProject(updated);
      addToast('Project updated successfully', 'safe');
    } catch (err: any) {
      addToast(err?.message || 'Failed to update project', 'high');
    } finally {
      setSavingGeneral(false);
    }
  };

  // API Key actions
  const handleGenerateKey = async (role: 'master' | 'viewer') => {
    if (!orgId || !projectId) return;
    try {
      const newKey = await orgApi.createProjectApiKey(
        orgId,
        projectId,
        `${role.toUpperCase()} Key`,
        role
      );
      setCreatedKey(newKey);
      setCopiedKey(false);
      setConfirmedSaved(false);
      await loadKeys();
      addToast(`${role.toUpperCase()} API key generated`, 'safe');
    } catch (err: any) {
      addToast(err?.message || `Failed to generate ${role} key`, 'high');
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    if (!orgId || !projectId) return;
    if (!confirm('Are you sure you want to revoke this API key? Ingestion will immediately halt.')) {
      return;
    }
    try {
      await orgApi.revokeProjectApiKey(orgId, projectId, keyId);
      await loadKeys();
      addToast('API key revoked', 'safe');
    } catch (err: any) {
      addToast(err?.message || 'Failed to revoke API key', 'high');
    }
  };

  const handleCopyNewKey = () => {
    if (!createdKey?.api_key) return;
    navigator.clipboard.writeText(createdKey.api_key);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 3000);
  };

  // Blocked Indicators actions
  const handleAddIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !indicatorValue.trim()) return;
    try {
      await orgApi.addBlockedIndicator(orgId, {
        indicator_type: indicatorType,
        indicator_value: indicatorValue.trim(),
        reason: indicatorReason.trim() || undefined,
        project_id: projectId || undefined,
      });
      setIndicatorValue('');
      setIndicatorReason('');
      setShowAddIndicator(false);
      await loadIndicators();
      addToast('Indicator permanently blocked', 'safe');
    } catch (err: any) {
      addToast(err?.message || 'Failed to block indicator', 'high');
    }
  };

  const handleDeleteIndicator = async (id: string) => {
    if (!orgId) return;
    try {
      await orgApi.deleteBlockedIndicator(orgId, id);
      await loadIndicators();
      addToast('Indicator unblocked', 'safe');
    } catch (err: any) {
      addToast(err?.message || 'Failed to delete indicator', 'high');
    }
  };

  // Members actions
  const handleInviteMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId || !inviteEmail.trim()) return;
    try {
      await orgApi.addMember(orgId, inviteEmail.trim(), inviteRole);
      setInviteEmail('');
      setShowInviteModal(false);
      await loadMembers();
      addToast('Member added to organization', 'safe');
    } catch (err: any) {
      addToast(err?.message || 'Failed to add member', 'high');
    }
  };

  const handleUpdateRole = async (memberId: string, newRole: string) => {
    if (!orgId) return;
    try {
      await orgApi.updateMemberRole(orgId, memberId, newRole);
      await loadMembers();
      addToast('Member role updated', 'safe');
    } catch (err: any) {
      addToast(err?.message || 'Failed to update member role', 'high');
    }
  };

  const handleRemoveMember = async (memberId: string) => {
    if (!orgId) return;
    if (!confirm('Are you sure you want to remove this member?')) return;
    try {
      await orgApi.removeMember(orgId, memberId);
      await loadMembers();
      addToast('Member removed', 'safe');
    } catch (err: any) {
      addToast(err?.message || 'Failed to remove member', 'high');
    }
  };

  const masterKey = apiKeys.find((k) => k.role === 'master' && k.status === 'active');
  const viewerKey = apiKeys.find((k) => k.role === 'viewer' && k.status === 'active');

  const gatewayUrl = `${window.location.origin}/api/v1/p/${project?.slug || ':slug'}/gateway`;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="border-b border-border pb-5">
        <h1 className="text-2xl font-bold tracking-tight text-text">Project Settings</h1>
        <p className="text-xs text-text-muted mt-1">
          Manage configuration, keys, indicators, and access policies for{' '}
          <span className="font-semibold text-text">{project?.name || 'Project'}</span>
        </p>
      </div>

      {/* Main Layout: Tabs + Content */}
      <div className="flex flex-col md:flex-row gap-6">
        {/* Sidebar Tabs */}
        <aside className="w-full md:w-56 shrink-0 space-y-1">
          <button
            type="button"
            onClick={() => setActiveTab('general')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'general'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-text-muted hover:bg-surface hover:text-text'
            }`}
          >
            <FolderOpen className="w-4 h-4" />
            <span>General</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('keys')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'keys'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-text-muted hover:bg-surface hover:text-text'
            }`}
          >
            <Key className="w-4 h-4" />
            <span>API Keys</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('indicators')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'indicators'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-text-muted hover:bg-surface hover:text-text'
            }`}
          >
            <Ban className="w-4 h-4" />
            <span>Blocked Indicators</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('members')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'members'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-text-muted hover:bg-surface hover:text-text'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Members</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('access')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'access'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-text-muted hover:bg-surface hover:text-text'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Gateway Access</span>
          </button>
        </aside>

        {/* Tab Content */}
        <main className="flex-1 bg-surface border border-border rounded-lg p-6">
          {/* TAB 1: GENERAL */}
          {activeTab === 'general' && (
            <div className="space-y-6 max-w-xl">
              <div>
                <h2 className="text-base font-semibold text-text">General Settings</h2>
                <p className="text-xs text-text-muted mt-0.5">
                  Update project metadata and identifiers.
                </p>
              </div>

              <form onSubmit={handleSaveGeneral} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-text-muted mb-1.5">
                    Project Name
                  </label>
                  <input
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    required
                    className="w-full bg-zinc-900 border border-border rounded-md px-3 py-2 text-xs text-text focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-text-muted mb-1.5">
                    Project Slug (Read-only)
                  </label>
                  <input
                    type="text"
                    value={project?.slug || ''}
                    disabled
                    className="w-full bg-zinc-900/50 border border-border rounded-md px-3 py-2 text-xs text-zinc-400 font-mono cursor-not-allowed"
                  />
                  <span className="text-[11px] text-text-muted mt-1 block">
                    Used in gateway endpoints: /api/v1/p/{project?.slug || ':slug'}/gateway
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1.5">
                      Status
                    </label>
                    <span className="inline-block px-2.5 py-1 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase">
                      {project?.status || 'active'}
                    </span>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1.5">
                      Created Date
                    </label>
                    <span className="text-xs text-zinc-300">
                      {project?.created_at ? new Date(project.created_at).toLocaleDateString() : '—'}
                    </span>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={savingGeneral}
                    className="flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-md bg-primary hover:bg-primary/90 text-primary-foreground transition-colors disabled:opacity-50"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>{savingGeneral ? 'Saving...' : 'Save Changes'}</span>
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* TAB 2: API KEYS */}
          {activeTab === 'keys' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-base font-semibold text-text">Project API Keys</h2>
                <p className="text-xs text-text-muted mt-0.5">
                  Each project supports exactly two key slots: one Master key (ingestion) and one Viewer key (read-only).
                </p>
              </div>

              {keysLoading ? (
                <p className="text-xs text-text-muted py-8 text-center">Loading keys...</p>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Master Key Card */}
                  <div className="bg-zinc-900/60 border border-border rounded-lg p-5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30 uppercase">
                          Master Slot
                        </span>
                        {masterKey ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            ACTIVE
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-zinc-800 text-zinc-400">
                            EMPTY SLOT
                          </span>
                        )}
                      </div>

                      <h3 className="text-sm font-semibold text-text mt-3">Ingestion Key (Master)</h3>
                      <p className="text-xs text-text-muted mt-1">
                        Authorizes high-throughput telemetry ingestion at the public gateway.
                      </p>

                      {masterKey ? (
                        <div className="mt-4 space-y-2 text-xs">
                          <div className="flex justify-between">
                            <span className="text-text-muted">Key Prefix:</span>
                            <span className="font-mono text-zinc-300">{masterKey.key_prefix}...</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-text-muted">Created:</span>
                            <span className="text-zinc-300">
                              {new Date(masterKey.created_at).toLocaleDateString()}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-text-muted">Last Used:</span>
                            <span className="text-zinc-300">
                              {masterKey.last_used_at ? new Date(masterKey.last_used_at).toLocaleDateString() : 'Never'}
                            </span>
                          </div>
                        </div>
                      ) : (
                        <p className="text-xs text-text-muted mt-4 italic">
                          No active master key. Generate one to begin ingesting telemetry.
                        </p>
                      )}
                    </div>

                    <div className="mt-6 pt-4 border-t border-border">
                      {masterKey ? (
                        <button
                          type="button"
                          onClick={() => handleRevokeKey(masterKey.id)}
                          className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>Revoke Master Key</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleGenerateKey('master')}
                          className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md bg-primary hover:bg-primary/90 text-primary-foreground transition-colors"
                        >
                          <Key className="w-3.5 h-3.5" />
                          <span>Generate Master Key</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Viewer Key Card */}
                  <div className="bg-zinc-900/60 border border-border rounded-lg p-5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/15 text-blue-400 border border-blue-500/30 uppercase">
                          Viewer Slot
                        </span>
                        {viewerKey ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            ACTIVE
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-zinc-800 text-zinc-400">
                            EMPTY SLOT
                          </span>
                        )}
                      </div>

                      <h3 className="text-sm font-semibold text-text mt-3">Read-Only Key (Viewer)</h3>
                      <p className="text-xs text-text-muted mt-1">
                        Read-only auditing access. Gateway rejects ingestion with 403 Forbidden.
                      </p>

                      {viewerKey ? (
                        <div className="mt-4 space-y-2 text-xs">
                          <div className="flex justify-between">
                            <span className="text-text-muted">Key Prefix:</span>
                            <span className="font-mono text-zinc-300">{viewerKey.key_prefix}...</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-text-muted">Created:</span>
                            <span className="text-zinc-300">
                              {new Date(viewerKey.created_at).toLocaleDateString()}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-text-muted">Last Used:</span>
                            <span className="text-zinc-300">
                              {viewerKey.last_used_at ? new Date(viewerKey.last_used_at).toLocaleDateString() : 'Never'}
                            </span>
                          </div>
                        </div>
                      ) : (
                        <p className="text-xs text-text-muted mt-4 italic">
                          No active viewer key. Generate one for external audit tools.
                        </p>
                      )}
                    </div>

                    <div className="mt-6 pt-4 border-t border-border">
                      {viewerKey ? (
                        <button
                          type="button"
                          onClick={() => handleRevokeKey(viewerKey.id)}
                          className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>Revoke Viewer Key</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleGenerateKey('viewer')}
                          className="w-full flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors"
                        >
                          <Key className="w-3.5 h-3.5" />
                          <span>Generate Viewer Key</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: BLOCKED INDICATORS */}
          {activeTab === 'indicators' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-base font-semibold text-text">Blocked Indicators (IOCs)</h2>
                  <p className="text-xs text-text-muted mt-0.5">
                    Traffic matching any active indicator is blocked at the gateway and flagged.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowAddIndicator(!showAddIndicator)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Block Indicator</span>
                </button>
              </div>

              {/* Add Indicator Form Modal / Expandable */}
              {showAddIndicator && (
                <form
                  onSubmit={handleAddIndicator}
                  className="bg-zinc-900 border border-border rounded-lg p-4 space-y-3"
                >
                  <h3 className="text-xs font-bold text-text uppercase tracking-wider">
                    Add Blocked Indicator
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="block text-[11px] text-text-muted mb-1">Type</label>
                      <select
                        value={indicatorType}
                        onChange={(e) => setIndicatorType(e.target.value as any)}
                        className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-xs text-text"
                      >
                        <option value="ip">IP Address</option>
                        <option value="domain">Domain</option>
                        <option value="email">Email</option>
                        <option value="hash">Hash</option>
                        <option value="actor">Threat Actor</option>
                      </select>
                    </div>

                    <div className="sm:col-span-2">
                      <label className="block text-[11px] text-text-muted mb-1">Indicator Value</label>
                      <input
                        type="text"
                        placeholder="e.g. 192.168.1.100 or evil.example.com"
                        value={indicatorValue}
                        onChange={(e) => setIndicatorValue(e.target.value)}
                        required
                        className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-xs text-text"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] text-text-muted mb-1">Reason (Optional)</label>
                    <input
                      type="text"
                      placeholder="e.g. Known C2 node from incident INC-441"
                      value={indicatorReason}
                      onChange={(e) => setIndicatorReason(e.target.value)}
                      className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-xs text-text"
                    />
                  </div>

                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowAddIndicator(false)}
                      className="px-3 py-1.5 text-xs rounded bg-zinc-800 text-zinc-300"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="px-3 py-1.5 text-xs rounded bg-red-600 hover:bg-red-700 text-white font-medium"
                    >
                      Enforce Block
                    </button>
                  </div>
                </form>
              )}

              {/* Indicators Table */}
              {indicators.length === 0 ? (
                <p className="text-xs text-text-muted py-8 text-center">
                  No indicators currently blocked in this workspace.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-border text-text-muted">
                        <th className="py-2 px-3">Type</th>
                        <th className="py-2 px-3">Value</th>
                        <th className="py-2 px-3">Reason</th>
                        <th className="py-2 px-3">Blocked At</th>
                        <th className="py-2 px-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50">
                      {indicators.map((ind) => (
                        <tr key={ind.id} className="hover:bg-zinc-900/30">
                          <td className="py-2.5 px-3">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-zinc-800 text-zinc-300">
                              {ind.indicator_type}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-text">{ind.indicator_value}</td>
                          <td className="py-2.5 px-3 text-text-muted">{ind.reason || '—'}</td>
                          <td className="py-2.5 px-3 text-text-muted">
                            {new Date(ind.blocked_at).toLocaleDateString()}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              type="button"
                              onClick={() => handleDeleteIndicator(ind.id)}
                              className="text-red-400 hover:text-red-300 p-1"
                              title="Delete indicator"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: MEMBERS */}
          {activeTab === 'members' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h2 className="text-base font-semibold text-text">Organization Members</h2>
                  <p className="text-xs text-text-muted mt-0.5">
                    Team members with access to this workspace and its projects.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowInviteModal(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-primary hover:bg-primary/90 text-primary-foreground transition-colors"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Invite Member</span>
                </button>
              </div>

              {/* Members Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-border text-text-muted">
                      <th className="py-2 px-3">User</th>
                      <th className="py-2 px-3">Role</th>
                      <th className="py-2 px-3">Joined</th>
                      <th className="py-2 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50">
                    {members.map((m) => (
                      <tr key={m.id} className="hover:bg-zinc-900/30">
                        <td className="py-2.5 px-3 font-medium text-text">{m.email}</td>
                        <td className="py-2.5 px-3">
                          <select
                            value={m.role}
                            onChange={(e) => handleUpdateRole(m.id, e.target.value)}
                            className="bg-zinc-900 border border-border text-[11px] rounded px-2 py-1 text-text"
                          >
                            <option value="admin">Admin</option>
                            <option value="analyst">Analyst</option>
                            <option value="viewer">Viewer</option>
                          </select>
                        </td>
                        <td className="py-2.5 px-3 text-text-muted">
                          {new Date(m.joined_at).toLocaleDateString()}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            type="button"
                            onClick={() => handleRemoveMember(m.id)}
                            className="text-red-400 hover:text-red-300 p-1"
                            title="Remove member"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 5: ACCESS (PUBLIC GATEWAY) */}
          {activeTab === 'access' && (
            <div className="space-y-6 max-w-2xl">
              <div>
                <h2 className="text-base font-semibold text-text">Public Gateway Access</h2>
                <p className="text-xs text-text-muted mt-0.5">
                  The unified ingestion endpoint for all analyzers in this project.
                </p>
              </div>

              {/* URL Display */}
              <div className="bg-zinc-900 border border-border rounded-lg p-4 space-y-2">
                <span className="text-[11px] font-semibold text-text-muted uppercase">
                  Gateway URL
                </span>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    readOnly
                    value={gatewayUrl}
                    className="flex-1 bg-surface border border-border rounded px-3 py-1.5 text-xs font-mono text-zinc-200"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(gatewayUrl);
                      addToast('Gateway URL copied', 'safe');
                    }}
                    className="px-3 py-1.5 text-xs rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 flex items-center gap-1.5"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </button>
                </div>
              </div>

              {/* cURL Example */}
              <div className="space-y-2">
                <span className="text-xs font-semibold text-text">Example Request (cURL)</span>
                <pre className="bg-zinc-950 border border-border rounded-lg p-4 text-[11px] font-mono text-zinc-300 overflow-x-auto leading-relaxed">
{`curl -X POST ${gatewayUrl} \\
  -H "Authorization: Bearer <cg_proj_live_YOUR_KEY>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "event_type": "log",
    "data": {
      "raw": "Failed password for root from 198.51.100.23 port 22 ssh2"
    }
  }'`}
                </pre>
              </div>

              {/* Key Role Details */}
              <div className="bg-zinc-900/40 border border-border rounded-lg p-4 space-y-3">
                <h3 className="text-xs font-bold text-text uppercase tracking-wider">
                  Role Enforcement
                </h3>
                <div className="space-y-2 text-xs">
                  <div className="flex items-start gap-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300">
                      MASTER
                    </span>
                    <p className="text-text-muted">
                      Full ingestion permission. Submits telemetry, runs active analyzers, and records new events.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300">
                      VIEWER
                    </span>
                    <p className="text-text-muted">
                      Read-only audit token. Rejected by gateway with <code className="text-red-400">403 Forbidden</code> on ingestion requests.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* PLAINTEXT-ONCE API KEY MODAL */}
      {createdKey && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400">
                <Key className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-text">Save Your New API Key</h3>
                <p className="text-xs text-text-muted">
                  This token will never be displayed again.
                </p>
              </div>
            </div>

            <div className="bg-amber-500/10 border border-amber-500/20 rounded-md p-3 text-xs text-amber-300 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Please copy and store this API key now. Once you close this modal, it cannot be retrieved.
              </span>
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-medium text-text-muted">API Token</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={createdKey.api_key}
                  className="flex-1 bg-zinc-950 border border-border rounded-md px-3 py-2 text-xs font-mono text-emerald-400 select-all"
                />
                <button
                  type="button"
                  onClick={handleCopyNewKey}
                  className="px-3 py-2 text-xs font-medium rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 flex items-center gap-1.5"
                >
                  {copiedKey ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  <span>{copiedKey ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2 pt-2">
              <input
                type="checkbox"
                id="confirm-saved"
                checked={confirmedSaved}
                onChange={(e) => setConfirmedSaved(e.target.checked)}
                className="rounded border-border text-primary focus:ring-primary w-4 h-4 bg-zinc-900"
              />
              <label htmlFor="confirm-saved" className="text-xs text-text-muted cursor-pointer">
                I have securely stored this key and understand it cannot be displayed again.
              </label>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                type="button"
                disabled={!confirmedSaved}
                onClick={() => setCreatedKey(null)}
                className="px-4 py-2 text-xs font-semibold rounded-md bg-primary hover:bg-primary/90 text-primary-foreground transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* INVITE MEMBER MODAL */}
      {showInviteModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-text">Invite Member</h3>
            <form onSubmit={handleInviteMember} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-muted mb-1">Email Address</label>
                <input
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  required
                  placeholder="analyst@example.com"
                  className="w-full bg-zinc-900 border border-border rounded-md px-3 py-2 text-xs text-text focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-text-muted mb-1">Role</label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as any)}
                  className="w-full bg-zinc-900 border border-border rounded-md px-3 py-2 text-xs text-text focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="admin">Admin</option>
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="px-3 py-1.5 text-xs rounded bg-zinc-800 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 text-xs font-medium rounded bg-primary hover:bg-primary/90 text-primary-foreground"
                >
                  Send Invite
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
