import { useAuthStore } from '../store/authStore';

/**
 * ORG-LIVE-VIEWS: resolve the current workspace mode from the auth store.
 *
 * ``isOrg`` is true only in a non-personal organization workspace — org-mode
 * rendering (live monitored streams, no entry forms) keys off it. Personal
 * workspaces keep the classic entry-form pages untouched.
 */
export function useOrgMode(): {
  isOrg: boolean;
  orgId: string | null;
  projectId: string | null;
  projectSlug: string | null;
} {
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const activeProject = useAuthStore((s) => s.activeProject);
  const isOrg = Boolean(activeOrganization && !activeOrganization.is_personal);
  return {
    isOrg,
    orgId: isOrg ? activeOrganization!.id : null,
    projectId: isOrg ? (activeProject?.id ?? null) : null,
    projectSlug: isOrg ? (activeProject?.slug ?? null) : null,
  };
}
