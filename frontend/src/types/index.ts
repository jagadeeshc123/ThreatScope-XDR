export interface Target {
  id: number;
  name: string;
  base_url: string;
  domain: string;
  environment: string;
  authorization_confirmed: boolean;
  created_at: string;
}

export interface Scan {
  id: number;
  target_id: number;
  profile: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at: string | null;
  total_findings: number;
  risk_score: number;
  overall_posture_score: number;
  posture_transport_security: number;
  posture_browser_defense: number;
  posture_session_safety: number;
  posture_exposure_hygiene: number;
  posture_authentication_surface: number;
  error_message: string | null;
}

export interface Finding {
  id: number;
  scan_id: number;
  target_id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  affected_url: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  confidence: string;
  risk_score: number;
  created_at: string;
}

export interface CrawlNode {
  id: number;
  scan_id: number;
  target_id: number;
  url: string;
  path: string;
  status_code: number | null;
  content_type: string | null;
  page_title: string | null;
  depth: number;
  parent_url: string | null;
  has_forms: boolean;
  has_password_field: boolean;
  finding_count: number;
  created_at: string;
}

export interface PostureDiff {
  id: number;
  current_scan_id: number;
  previous_scan_id: number;
  target_id: number;
  new_findings_count: number;
  resolved_findings_count: number;
  unchanged_findings_count: number;
  risk_score_delta: number;
  posture_score_delta: number;
  summary: string | null;
  created_at: string;
}

export interface EvidenceArtifact {
  id: number;
  scan_id: number;
  target_id: number;
  artifact_type: string;
  title: string;
  file_path: string | null;
  redacted_text: string | null;
  related_url: string | null;
  created_at: string;
}

export interface Report {
  id: number;
  scan_id: number;
  target_id: number;
  title: string;
  executive_summary: string;
  html_content: string;
  created_at: string;
}

export interface DashboardSummary {
  total_targets: number;
  total_scans: number;
  active_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  overall_risk_score: number;
  overall_posture_score: number;
  api_assessment_count: number;
  api_endpoint_count: number;
  api_unauthenticated_endpoint_count: number;
  api_high_risk_endpoint_count: number;
  severity_distribution: Record<string, number>;
  recent_scans: Scan[];
  highest_risk_targets: Target[];
}

export interface Notification {
  id: number;
  title: string;
  message: string;
  type: 'info' | 'success' | 'warning' | 'danger';
  entity_type: string;
  entity_id: number | null;
  is_read: boolean;
  created_at: string;
}

export interface UserProfile {
  id: number;
  full_name: string;
  email: string;
  organization: string;
  role: string;
  avatar_initials: string;
  created_at: string;
  updated_at: string;
}

export interface AppSettings {
  id: number;
  theme: 'dark' | 'light' | 'system';
  default_scan_profile: string;
  request_timeout_seconds: number;
  max_pages_standard: number;
  max_pages_full: number;
  max_depth_standard: number;
  max_depth_full: number;
  rate_limit_delay_ms: number;
  report_company_name: string;
  report_footer_text: string;
  auto_generate_report: boolean;
  created_at: string;
  updated_at: string;
}

export interface SearchResults {
  targets: Target[];
  scans: Scan[];
  findings: Finding[];
  reports: Report[];
  api_assessments: ApiAssessment[];
  api_endpoints: ApiEndpoint[];
}

export type ApiSourceType = 'openapi' | 'postman' | 'manual';
export type ApiAssessmentStatus = 'draft' | 'processing' | 'completed' | 'failed';
export type ApiRiskLevel = 'info' | 'low' | 'medium' | 'high';

export interface ApiAssessment {
  id: number;
  name: string;
  description: string | null;
  source_type: ApiSourceType;
  source_filename: string | null;
  status: ApiAssessmentStatus;
  base_url: string | null;
  api_version: string | null;
  endpoint_count: number;
  unauthenticated_endpoint_count: number;
  high_risk_endpoint_count: number;
  risk_score: number;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApiImportArtifact {
  id: number;
  assessment_id: number;
  artifact_type: 'openapi' | 'postman';
  filename: string;
  parsed_summary: Record<string, unknown>;
  created_at: string;
}

export interface ApiAssessmentDetail extends ApiAssessment {
  artifacts: ApiImportArtifact[];
}

export interface ApiEndpoint {
  id: number;
  assessment_id: number;
  path: string;
  method: string;
  operation_id: string | null;
  summary: string | null;
  description: string | null;
  auth_required: boolean;
  auth_schemes: string[];
  request_content_types: string[];
  response_content_types: string[];
  parameters: Array<Record<string, unknown>>;
  tags: string[];
  folder_path: string | null;
  deprecated: boolean;
  preliminary_risk_level: ApiRiskLevel;
  preliminary_risk_reasons: string[];
  created_at: string;
}

export interface ApiSecurityOverview {
  total_assessments: number;
  endpoints_inventoried: number;
  unauthenticated_endpoints: number;
  high_risk_endpoints: number;
  recent_assessments: ApiAssessment[];
}

export interface ApiSecuritySummary {
  assessment: ApiAssessment;
  endpoint_count: number;
  unauthenticated_endpoint_count: number;
  high_risk_endpoint_count: number;
  risk_distribution: Record<ApiRiskLevel, number>;
  methods: Record<string, number>;
  tags: string[];
}

export interface ApiImportResult {
  assessment: ApiAssessment;
  artifact: ApiImportArtifact;
  endpoints_discovered: number;
  unauthenticated_endpoints: number;
  high_risk_endpoints: number;
}
