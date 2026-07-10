import type {
  AppSettings,
  CrawlNode,
  DashboardSummary,
  EvidenceArtifact,
  Finding,
  Notification,
  PostureDiff,
  Report,
  Scan,
  SearchResults,
  Target,
  UserProfile,
} from '../types';
import { apiClient } from './client';

export interface TargetCreatePayload {
  name: string;
  base_url: string;
  environment: string;
  authorization_confirmed: boolean;
}

export type TargetUpdatePayload = Partial<TargetCreatePayload>;

export interface ScanCreatePayload {
  target_id: number;
  profile: string;
}

export interface PolicyResultCheck {
  check_id: string;
  title: string;
  status: 'passed' | 'failed';
  violating_findings: string[];
}

export interface PolicyResultPack {
  policy_id: string;
  title: string;
  checks: PolicyResultCheck[];
}

export interface PolicyCheck {
  id: string;
  title: string;
  expected_state: string;
  severity_impact: string;
  related_finding_titles?: string[];
}

export interface PolicyPack {
  policy_id: string;
  title: string;
  description: string;
  checks: PolicyCheck[];
}

export type UserProfileUpdatePayload = Partial<Pick<
  UserProfile,
  'full_name' | 'email' | 'organization' | 'role' | 'avatar_initials'
>>;

export type AppSettingsUpdatePayload = Partial<Pick<
  AppSettings,
  | 'theme'
  | 'default_scan_profile'
  | 'request_timeout_seconds'
  | 'max_pages_standard'
  | 'max_pages_full'
  | 'max_depth_standard'
  | 'max_depth_full'
  | 'rate_limit_delay_ms'
  | 'report_company_name'
  | 'report_footer_text'
  | 'auto_generate_report'
>>;

export const VULNSCOPE_EVENTS = {
  profileUpdated: 'vulnscope:profile-updated',
  notificationsUpdated: 'vulnscope:notifications-updated',
} as const;

const data = <T,>(request: Promise<{ data: T }>) => request.then(response => response.data);

const dispatch = (eventName: string) => {
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(eventName));
};

export const vulnscopeApi = {
  getDashboardSummary: () => data<DashboardSummary>(apiClient.get('/dashboard/summary')),

  listTargets: () => data<Target[]>(apiClient.get('/targets/')),
  createTarget: (payload: TargetCreatePayload) => data<Target>(apiClient.post('/targets/', payload)),
  updateTarget: (targetId: number, payload: TargetUpdatePayload) => data<Target>(apiClient.patch(`/targets/${targetId}`, payload)),
  deleteTarget: (targetId: number) => data<{ ok: boolean }>(apiClient.delete(`/targets/${targetId}`)).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),

  listScans: () => data<Scan[]>(apiClient.get('/scans/')),
  startScan: (payload: ScanCreatePayload) => data<Scan>(apiClient.post('/scans/start', payload)),
  getScan: (scanId: number) => data<Scan>(apiClient.get(`/scans/${scanId}`)),
  deleteScan: (scanId: number) => data<{ ok: boolean }>(apiClient.delete(`/scans/${scanId}`)).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),
  listFindings: (scanId: number) => data<Finding[]>(apiClient.get(`/scans/${scanId}/findings`)),
  listCrawlNodes: (scanId: number) => data<CrawlNode[]>(apiClient.get(`/scans/${scanId}/crawl-map`)),
  getPostureDiff: (scanId: number) => data<PostureDiff>(apiClient.get(`/scans/${scanId}/diff`)),
  listEvidence: (scanId: number) => data<EvidenceArtifact[]>(apiClient.get(`/scans/${scanId}/evidence`)),
  getPolicyResults: (scanId: number) => data<PolicyResultPack[]>(apiClient.get(`/scans/${scanId}/policy-results`)),

  listReports: () => data<Report[]>(apiClient.get('/reports/')),
  getReport: (reportId: number) => data<Report>(apiClient.get(`/reports/${reportId}`)),
  generateReport: (scanId: number) => data<Report>(apiClient.post(`/reports/generate/${scanId}`)).then(report => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return report;
  }),
  downloadReport: (reportId: number) => data<Blob>(apiClient.get(`/reports/${reportId}/download`, { responseType: 'blob' })),
  deleteReport: (reportId: number) => data<{ ok: boolean }>(apiClient.delete(`/reports/${reportId}`)).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),

  listPolicies: () => data<PolicyPack[]>(apiClient.get('/policies/')),
  search: (query: string) => data<SearchResults>(apiClient.get('/search/', { params: { q: query } })),

  listNotifications: (limit = 50) => data<Notification[]>(apiClient.get('/notifications/', { params: { limit } })),
  getUnreadNotificationCount: () => data<{ unread_count: number }>(apiClient.get('/notifications/unread-count')),
  markNotificationRead: (notificationId: number) => data<Notification>(apiClient.patch(`/notifications/${notificationId}/read`)).then(notification => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return notification;
  }),
  markAllNotificationsRead: () => data<{ status: string }>(apiClient.patch('/notifications/mark-all-read')).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),
  deleteNotification: (notificationId: number) => data<{ status: string }>(apiClient.delete(`/notifications/${notificationId}`)).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),

  getProfile: () => data<UserProfile>(apiClient.get('/profile/')),
  updateProfile: (payload: UserProfileUpdatePayload) => data<UserProfile>(apiClient.patch('/profile/', payload)).then(profile => {
    dispatch(VULNSCOPE_EVENTS.profileUpdated);
    return profile;
  }),

  getSettings: () => data<AppSettings>(apiClient.get('/settings/')),
  updateSettings: (payload: AppSettingsUpdatePayload) => data<AppSettings>(apiClient.patch('/settings/', payload)),
  resetSettings: () => data<AppSettings>(apiClient.post('/settings/reset')),
};
