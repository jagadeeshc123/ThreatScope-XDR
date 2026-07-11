import type {
  AppSettings,
  ApiAssessment,
  ApiBusinessFlow,
  ApiBusinessFlowAnalysis,
  ApiBusinessFlowRisk,
  ApiBusinessFlowStep,
  ApiIdentity,
  ApiRole,
  AuthorizationGenerationResult,
  AuthorizationMatrixEntry,
  AuthorizationReview,
  ApiAssessmentDetail,
  ApiEndpoint,
  ApiFinding,
  ApiImportResult,
  ApiOwaspCoverage,
  ApiReport,
  AnalyzeAssessmentResult,
  JwtAnalysis,
  ResponseExposureItem,
  ApiSecurityOverview,
  ApiSecuritySummary,
  ApiSourceType,
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
  SocAlert, SocAlertDetail, SocBlocklistEntry, SocDetectionRule, SocDetectionRunResult, SocEvent, SocLogImport, SocLogSource, SocOverview, SocPage, SocReport, SocSimulatorResult, SocThreatIntelResult,
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

export interface ApiAssessmentCreatePayload {
  name: string;
  description?: string | null;
  source_type: ApiSourceType;
}

export interface ApiEndpointFilters {
  method?: string;
  auth?: 'authenticated' | 'unauthenticated';
  deprecated?: boolean;
  risk?: 'info' | 'low' | 'medium' | 'high';
  tag?: string;
  q?: string;
  sort?: 'method' | 'path' | 'authentication' | 'risk';
}

export interface JwtAnalyzePayload {
  token: string;
  assessment_id?: number | null;
  expected_issuer?: string | null;
  expected_audience?: string | null;
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

  getApiSecurityOverview: () => data<ApiSecurityOverview>(apiClient.get('/api-security/overview')),
  listApiAssessments: () => data<ApiAssessment[]>(apiClient.get('/api-security/assessments')),
  createApiAssessment: (payload: ApiAssessmentCreatePayload) => data<ApiAssessment>(apiClient.post('/api-security/assessments', payload)).then(assessment => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return assessment;
  }),
  getApiAssessment: (assessmentId: number) => data<ApiAssessmentDetail>(apiClient.get(`/api-security/assessments/${assessmentId}`)),
  deleteApiAssessment: (assessmentId: number) => data<{ ok: boolean }>(apiClient.delete(`/api-security/assessments/${assessmentId}`)).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),
  importOpenApi: (assessmentId: number, file: File) => {
    const form = new FormData();
    form.append('file', file);
    return data<ApiImportResult>(apiClient.post(`/api-security/assessments/${assessmentId}/import/openapi`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })).then(result => {
      dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
      return result;
    });
  },
  importPostman: (assessmentId: number, file: File) => {
    const form = new FormData();
    form.append('file', file);
    return data<ApiImportResult>(apiClient.post(`/api-security/assessments/${assessmentId}/import/postman`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })).then(result => {
      dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
      return result;
    });
  },
  listApiEndpoints: (assessmentId: number, filters: ApiEndpointFilters = {}) => data<ApiEndpoint[]>(apiClient.get(`/api-security/assessments/${assessmentId}/endpoints`, { params: filters })),
  getApiSecuritySummary: (assessmentId: number) => data<ApiSecuritySummary>(apiClient.get(`/api-security/assessments/${assessmentId}/summary`)),
  analyzeApiAssessment: (assessmentId: number) => data<AnalyzeAssessmentResult>(apiClient.post(`/api-security/assessments/${assessmentId}/analyze`)).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),
  listApiFindings: (assessmentId: number, filters: { severity?: string; source?: string } = {}) => data<ApiFinding[]>(apiClient.get(`/api-security/assessments/${assessmentId}/findings`, { params: filters })),
  getApiFinding: (findingId: number) => data<ApiFinding>(apiClient.get(`/api-security/findings/${findingId}`)),
  getApiOwaspCoverage: (assessmentId: number) => data<ApiOwaspCoverage[]>(apiClient.get(`/api-security/assessments/${assessmentId}/owasp-coverage`)),
  getResponseExposure: (assessmentId: number) => data<ResponseExposureItem[]>(apiClient.get(`/api-security/assessments/${assessmentId}/response-exposure`)),
  generateApiReport: (assessmentId: number) => data<ApiReport>(apiClient.post(`/api-security/assessments/${assessmentId}/reports`)).then(report => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return report;
  }),
  listApiReports: (assessmentId: number) => data<ApiReport[]>(apiClient.get(`/api-security/assessments/${assessmentId}/reports`)),
  getApiReport: (reportId: number) => data<ApiReport>(apiClient.get(`/api-security/reports/${reportId}`)),
  downloadApiReport: (reportId: number) => data<Blob>(apiClient.get(`/api-security/reports/${reportId}/download`, { responseType: 'blob' })),
  analyzeJwt: (payload: JwtAnalyzePayload) => data<JwtAnalysis>(apiClient.post('/api-security/jwt/analyze', payload)).then(result => {
    dispatch(VULNSCOPE_EVENTS.notificationsUpdated);
    return result;
  }),
  listJwtAnalyses: (assessmentId?: number) => data<JwtAnalysis[]>(apiClient.get('/api-security/jwt/analyses', { params: assessmentId ? { assessment_id: assessmentId } : {} })),
  getJwtAnalysis: (analysisId: number) => data<JwtAnalysis>(apiClient.get(`/api-security/jwt/analyses/${analysisId}`)),
  deleteJwtAnalysis: (analysisId: number) => data<{ ok: boolean }>(apiClient.delete(`/api-security/jwt/analyses/${analysisId}`)),

  listApiRoles: (assessmentId: number) => data<ApiRole[]>(apiClient.get(`/api-security/assessments/${assessmentId}/roles`)),
  createApiRole: (assessmentId: number, payload: Pick<ApiRole, 'name' | 'privilege_level'> & { description?: string | null }) => data<ApiRole>(apiClient.post(`/api-security/assessments/${assessmentId}/roles`, payload)),
  updateApiRole: (roleId: number, payload: Partial<Pick<ApiRole, 'name' | 'description' | 'privilege_level'>>) => data<ApiRole>(apiClient.patch(`/api-security/roles/${roleId}`, payload)),
  deleteApiRole: (roleId: number) => data<{ ok: boolean }>(apiClient.delete(`/api-security/roles/${roleId}`)),
  listApiIdentities: (assessmentId: number) => data<ApiIdentity[]>(apiClient.get(`/api-security/assessments/${assessmentId}/identities`)),
  createApiIdentity: (assessmentId: number, payload: Pick<ApiIdentity, 'label' | 'role_id' | 'identity_type'> & { notes?: string | null }) => data<ApiIdentity>(apiClient.post(`/api-security/assessments/${assessmentId}/identities`, payload)),
  updateApiIdentity: (identityId: number, payload: Partial<Pick<ApiIdentity, 'label' | 'role_id' | 'identity_type' | 'notes'>>) => data<ApiIdentity>(apiClient.patch(`/api-security/identities/${identityId}`, payload)),
  deleteApiIdentity: (identityId: number) => data<{ ok: boolean }>(apiClient.delete(`/api-security/identities/${identityId}`)),
  listAuthorizationMatrix: (assessmentId: number) => data<AuthorizationMatrixEntry[]>(apiClient.get(`/api-security/assessments/${assessmentId}/authorization-matrix`)),
  createAuthorizationMatrixEntry: (assessmentId: number, payload: Pick<AuthorizationMatrixEntry, 'endpoint_id' | 'role_id' | 'expected_access' | 'object_scope'> & Partial<Pick<AuthorizationMatrixEntry, 'expected_conditions' | 'analyst_notes' | 'review_status'>>) => data<AuthorizationMatrixEntry>(apiClient.post(`/api-security/assessments/${assessmentId}/authorization-matrix`, payload)),
  updateAuthorizationMatrixEntry: (entryId: number, payload: Partial<Pick<AuthorizationMatrixEntry, 'expected_access' | 'object_scope' | 'expected_conditions' | 'analyst_notes' | 'review_status'>>) => data<AuthorizationMatrixEntry>(apiClient.patch(`/api-security/authorization-matrix/${entryId}`, payload)),
  deleteAuthorizationMatrixEntry: (entryId: number) => data<{ ok: boolean }>(apiClient.delete(`/api-security/authorization-matrix/${entryId}`)),
  generateAuthorizationReview: (assessmentId: number) => data<AuthorizationGenerationResult>(apiClient.post(`/api-security/assessments/${assessmentId}/authorization-review/generate`)).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),
  listAuthorizationReviews: (assessmentId: number) => data<AuthorizationReview[]>(apiClient.get(`/api-security/assessments/${assessmentId}/authorization-reviews`)),
  updateAuthorizationReview: (reviewId: number, payload: Partial<Pick<AuthorizationReview, 'analyst_decision' | 'notes'>>) => data<AuthorizationReview>(apiClient.patch(`/api-security/authorization-reviews/${reviewId}`, payload)).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),
  listBusinessFlows: (assessmentId: number) => data<ApiBusinessFlow[]>(apiClient.get(`/api-security/assessments/${assessmentId}/business-flows`)),
  createBusinessFlow: (assessmentId: number, payload: Pick<ApiBusinessFlow, 'name' | 'description' | 'actor_roles'> & Partial<Pick<ApiBusinessFlow, 'business_goal' | 'status'>>) => data<ApiBusinessFlow>(apiClient.post(`/api-security/assessments/${assessmentId}/business-flows`, payload)),
  getBusinessFlow: (flowId: number) => data<ApiBusinessFlow>(apiClient.get(`/api-security/business-flows/${flowId}`)),
  updateBusinessFlow: (flowId: number, payload: Partial<Pick<ApiBusinessFlow, 'name' | 'description' | 'business_goal' | 'actor_roles' | 'status'>>) => data<ApiBusinessFlow>(apiClient.patch(`/api-security/business-flows/${flowId}`, payload)),
  deleteBusinessFlow: (flowId: number) => data<{ ok: boolean }>(apiClient.delete(`/api-security/business-flows/${flowId}`)),
  createBusinessFlowStep: (flowId: number, payload: Omit<ApiBusinessFlowStep, 'id' | 'flow_id' | 'created_at' | 'updated_at'>) => data<ApiBusinessFlowStep>(apiClient.post(`/api-security/business-flows/${flowId}/steps`, payload)),
  updateBusinessFlowStep: (stepId: number, payload: Partial<Omit<ApiBusinessFlowStep, 'id' | 'flow_id' | 'created_at' | 'updated_at'>>) => data<ApiBusinessFlowStep>(apiClient.patch(`/api-security/business-flow-steps/${stepId}`, payload)),
  deleteBusinessFlowStep: (stepId: number) => data<{ ok: boolean }>(apiClient.delete(`/api-security/business-flow-steps/${stepId}`)),
  analyzeBusinessFlow: (flowId: number) => data<ApiBusinessFlowAnalysis>(apiClient.post(`/api-security/business-flows/${flowId}/analyze`)).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),
  listBusinessFlowRisks: (flowId: number) => data<ApiBusinessFlowRisk[]>(apiClient.get(`/api-security/business-flows/${flowId}/risks`)),
  updateBusinessFlowRisk: (riskId: number, status: ApiBusinessFlowRisk['status']) => data<ApiBusinessFlowRisk>(apiClient.patch(`/api-security/business-flow-risks/${riskId}`, { status })).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),

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

  getSocOverview: () => data<SocOverview>(apiClient.get('/soc/overview')),
  listSocSources: () => data<SocLogSource[]>(apiClient.get('/soc/sources')),
  createSocSource: (payload: Pick<SocLogSource, 'name' | 'description' | 'source_type' | 'parser_type' | 'enabled'>) => data<SocLogSource>(apiClient.post('/soc/sources', payload)),
  updateSocSource: (id: number, payload: Partial<Pick<SocLogSource, 'name' | 'description' | 'source_type' | 'parser_type' | 'enabled'>>) => data<SocLogSource>(apiClient.patch(`/soc/sources/${id}`, payload)),
  deleteSocSource: (id: number) => data<{ ok: boolean }>(apiClient.delete(`/soc/sources/${id}`)),
  importSocLog: (sourceId: number, file: File) => { const form = new FormData(); form.append('file', file); return data<SocLogImport>(apiClient.post(`/soc/sources/${sourceId}/imports`, form, { headers: { 'Content-Type': 'multipart/form-data' } })).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }); },
  listSocImports: (sourceId?: number) => data<SocLogImport[]>(apiClient.get('/soc/imports', { params: sourceId ? { source_id: sourceId } : {} })),
  listSocEvents: (params: Record<string, string | number | undefined> = {}) => data<SocPage<SocEvent>>(apiClient.get('/soc/events', { params })),
  getSocEvent: (id: number) => data<SocEvent>(apiClient.get(`/soc/events/${id}`)),
  listSocRules: () => data<SocDetectionRule[]>(apiClient.get('/soc/rules')),
  createSocRule: (payload: Omit<SocDetectionRule, 'id' | 'is_default' | 'created_at' | 'updated_at'>) => data<SocDetectionRule>(apiClient.post('/soc/rules', payload)),
  updateSocRule: (id: number, payload: Partial<Pick<SocDetectionRule, 'name' | 'description' | 'enabled' | 'severity' | 'confidence' | 'window_seconds' | 'threshold' | 'group_by' | 'conditions_json' | 'remediation'>>) => data<SocDetectionRule>(apiClient.patch(`/soc/rules/${id}`, payload)),
  deleteSocRule: (id: number) => data<{ ok: boolean }>(apiClient.delete(`/soc/rules/${id}`)),
  generateSocEvents: (payload: { scenario: string; number_of_events: number; seed: number; start_time?: string; source_id?: number }) => data<SocSimulatorResult>(apiClient.post('/soc/simulator/generate', payload)),
  runSocDetections: (payload: { rule_ids?: number[]; source_id?: number; start_time?: string; end_time?: string } = {}) => data<SocDetectionRunResult>(apiClient.post('/soc/detections/run', payload)).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),
  listSocAlerts: (params: Record<string, string | number | undefined> = {}) => data<SocPage<SocAlert>>(apiClient.get('/soc/alerts', { params })),
  getSocAlert: (id: number) => data<SocAlertDetail>(apiClient.get(`/soc/alerts/${id}`)),
  updateSocAlert: (id: number, payload: Partial<Pick<SocAlert, 'status' | 'analyst_notes'>>) => data<SocAlert>(apiClient.patch(`/soc/alerts/${id}`, payload)),
  enrichSocIndicator: (payload: { alert_id?: number; indicator_type: string; indicator_value: string }) => data<SocThreatIntelResult>(apiClient.post('/soc/enrichment', payload)).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),
  listSocBlocklist: () => data<SocBlocklistEntry[]>(apiClient.get('/soc/blocklist')),
  createSocBlocklistEntry: (payload: { indicator_type: string; indicator_value: string; reason: string; source_alert_id?: number; expires_at?: string }) => data<SocBlocklistEntry>(apiClient.post('/soc/blocklist', payload)).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),
  updateSocBlocklistEntry: (id: number, payload: Partial<Pick<SocBlocklistEntry, 'reason' | 'status' | 'expires_at'>>) => data<SocBlocklistEntry>(apiClient.patch(`/soc/blocklist/${id}`, payload)),
  deleteSocBlocklistEntry: (id: number) => data<{ ok: boolean }>(apiClient.delete(`/soc/blocklist/${id}`)),
  listSocReports: () => data<SocReport[]>(apiClient.get('/soc/reports')),
  createSocReport: () => data<SocReport>(apiClient.post('/soc/reports', { report_type: 'soc_summary' })).then(result => { dispatch(VULNSCOPE_EVENTS.notificationsUpdated); return result; }),
  getSocReport: (id: number) => data<SocReport>(apiClient.get(`/soc/reports/${id}`)),
  downloadSocReport: (id: number) => data<Blob>(apiClient.get(`/soc/reports/${id}/download`, { responseType: 'blob' })),
};
