import OrgLiveStream from './OrgLiveStream';
import { useOrgMode } from '../../hooks/useOrgMode';
import AccountTakeover from '../../pages/AccountTakeover';
import DeepfakeAnalysis from '../../pages/DeepfakeAnalysis';
import ImpersonationAnalysis from '../../pages/ImpersonationAnalysis';
import LogAnalysis from '../../pages/LogAnalysis';
import NetworkThreats from '../../pages/NetworkThreats';
import PhishingAnalysis from '../../pages/PhishingAnalysis';
import UrlAnalysis from '../../pages/UrlAnalysis';
import type { StreamFeature } from '../../services/orgApi';

/**
 * ORG-LIVE-VIEWS: route-level mode gate for the seven feature pages.
 *
 * In a non-personal organization workspace the route renders the read-only
 * Splunk-style OrgLiveStream for the feature; in personal workspaces the
 * original entry-form page renders COMPLETELY UNTOUCHED (these wrappers are
 * the only switch — the personal page files have zero org-mode code).
 *
 * Why a wrapper instead of an early return inside each page component: an
 * early return placed before that component's hooks breaks the Rules of
 * Hooks when the workspace switches while the route stays mounted (the hook
 * count would change between renders). The gate lives one level up where
 * each branch mounts a fresh, hook-consistent component.
 */
function orgGate(feature: StreamFeature, title: string, description: string, Personal: () => JSX.Element) {
  return function FeatureView() {
    const { isOrg } = useOrgMode();
    if (isOrg) return <OrgLiveStream feature={feature} title={title} description={description} />;
    return <Personal />;
  };
}

export const PhishingAnalysisView = orgGate(
  'phishing',
  'Phishing — Live Monitored Events',
  'Read-only Splunk-style stream of phishing events ingested via the project gateway, mail connectors, and the realtime pipeline. Analyze new content from your personal workspace.',
  PhishingAnalysis,
);

export const UrlAnalysisView = orgGate(
  'url',
  'URL Threats — Live Monitored Events',
  'Read-only stream of malicious-URL detections monitored across the organization. Analyze a single URL from your personal workspace.',
  UrlAnalysis,
);

export const ImpersonationView = orgGate(
  'impersonation',
  'Impersonation — Live Monitored Events',
  'Read-only stream of brand / executive impersonation and BEC detections monitored across the organization. Analyze a message from your personal workspace.',
  ImpersonationAnalysis,
);

export const DeepfakeAnalysisView = orgGate(
  'deepfake',
  'Deepfake — Live Monitored Events',
  'Read-only stream of media-forensics verdicts monitored across the organization. Analyze a media file from your personal workspace.',
  DeepfakeAnalysis,
);

export const LogAnalysisView = orgGate(
  'logs',
  'Log Analysis — Live Monitored Events',
  'Read-only Splunk-style stream of gateway-ingested auth, network and application logs with detector verdicts. Paste-box analysis lives in your personal workspace.',
  LogAnalysis,
);

export const NetworkThreatsView = orgGate(
  'network',
  'Network & API — Live Monitored Events',
  'Read-only stream of network and API-abuse events monitored across the organization.',
  NetworkThreats,
);

export const AccountTakeoverView = orgGate(
  'ato',
  'Account Takeover — Live Monitored Events',
  'Read-only stream of credential-theft and account-takeover signals monitored across the organization.',
  AccountTakeover,
);
