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
  api_finding_count: number;
  api_high_risk_finding_count: number;
  api_owasp_observed_category_count: number;
  api_authorization_matrix_coverage: number;
  api_unresolved_authorization_review_count: number;
  api_business_flow_count: number;
  api_high_risk_flow_indicator_count: number;
  soc_total_events: number;
  soc_open_alerts: number;
  soc_high_critical_alerts: number;
  soc_active_rules: number;
  soc_active_blocklist_entries: number;
  document_total_analyses: number;
  document_suspicious_high_risk: number;
  document_high_critical_findings: number;
  document_active_content: number;
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
  api_findings: ApiFinding[];
  jwt_analyses: JwtAnalysis[];
  api_reports: ApiReport[];
  api_roles: ApiRole[];
  authorization_reviews: AuthorizationReview[];
  api_business_flows: ApiBusinessFlow[];
  api_business_flow_risks: ApiBusinessFlowRisk[];
  soc_events: Array<Pick<SocEvent, 'id' | 'event_type' | 'severity' | 'event_time' | 'source_ip' | 'username'> & { snippet: string }>;
  soc_alerts: Array<Pick<SocAlert, 'id' | 'title' | 'severity' | 'status'> & { snippet: string }>;
  soc_rules: Array<Pick<SocDetectionRule, 'id' | 'rule_code' | 'name' | 'severity' | 'enabled'>>;
  soc_reports: Array<Pick<SocReport, 'id' | 'title' | 'created_at'>>;
  soc_blocklist_entries: Array<Pick<SocBlocklistEntry, 'id' | 'indicator_type' | 'indicator_value' | 'status' | 'reason'>>;
  document_analyses: Array<Pick<DocumentAnalysis, 'id' | 'filename_sanitized' | 'file_hash' | 'classification' | 'risk_score' | 'created_at'>>;
  document_findings: Array<Pick<DocumentFinding, 'id' | 'analysis_id' | 'rule_code' | 'title' | 'severity'> & { snippet: string }>;
  document_indicators: Array<Pick<DocumentIndicator, 'id' | 'analysis_id' | 'indicator_type' | 'display_value_redacted'> & { snippet: string }>;
  document_reports: Array<Pick<DocumentReport, 'id' | 'analysis_id' | 'title' | 'created_at'>>;
}

export type DocumentClassification = 'low_observed_risk' | 'needs_review' | 'suspicious' | 'high_risk' | 'unknown';
export interface DocumentAnalysis { id:number; filename_sanitized:string; file_hash:string; file_size:number; mime_type:string; pdf_version:string|null; page_count:number|null; analysis_status:'pending'|'processing'|'completed'|'limited'|'failed'; is_encrypted:boolean; encryption_limited_analysis:boolean; has_javascript:boolean; has_open_action:boolean; has_additional_actions:boolean; has_launch_action:boolean; has_acroform:boolean; has_xfa:boolean; has_embedded_files:boolean; has_external_uris:boolean; external_uri_count:number; embedded_file_count:number; annotation_count:number; metadata_json_redacted:Record<string,unknown>; feature_summary_json:Record<string,unknown>; extracted_text_character_count:number; risk_score:number; classification:DocumentClassification; confidence:'low'|'medium'|'high'; methodology:string; error_summary:string|null; created_at:string; completed_at:string|null; duplicate_existing:boolean; }
export interface DocumentFinding { id:number; analysis_id:number; rule_code:string; title:string; category:string; severity:SocSeverity; confidence:SocConfidence; description:string; evidence_summary:string; technical_impact:string; possible_business_impact:string; remediation:string; manual_validation_required:boolean; fingerprint:string; created_at:string; }
export interface DocumentIndicator { id:number; analysis_id:number; indicator_type:'url'|'domain'|'ip'|'email'|'filename'|'file_hash'|'action'|'script_reference'; normalized_value:string; display_value_redacted:string; context:string; severity:SocSeverity; confidence:SocConfidence; source_object:string|null; created_at:string; }
export interface DocumentEmbeddedArtifact { id:number; analysis_id:number; filename_sanitized:string; extension:string|null; declared_mime_type:string|null; file_size:number|null; sha256:string|null; artifact_type:string; executable_like:boolean; archive_like:boolean; script_like:boolean; office_macro_like:boolean; risk_label:string; evidence_summary:string; created_at:string; }
export interface DocumentAnalysisDetail extends DocumentAnalysis { findings:DocumentFinding[]; indicators:DocumentIndicator[]; embedded_artifacts:DocumentEmbeddedArtifact[]; }
export interface DocumentAnalysisPage { items:DocumentAnalysis[]; total:number; page:number; page_size:number; }
export interface DocumentReport { id:number; analysis_id:number|null; title:string; html_content:string; summary_json:Record<string,unknown>; created_at:string; }
export interface DocumentOverview { total_analyses:number; analyses_last_24_hours:number; completed_analyses:number; failed_or_limited_analyses:number; suspicious_analyses:number; high_risk_analyses:number; total_findings:number; high_critical_findings:number; documents_with_javascript:number; documents_with_automatic_actions:number; documents_with_embedded_artifacts:number; documents_with_external_links:number; findings_by_severity:Record<string,number>; analyses_by_classification:Record<string,number>; recent_analyses:DocumentAnalysis[]; top_finding_categories:Array<{category:string;count:number}>; recent_activity:Array<{id:number;action:string;message:string;created_at:string}>; }

export type SocSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type SocConfidence = 'low' | 'medium' | 'high';
export type SocEventType = 'authentication' | 'authorization' | 'web_request' | 'api_request' | 'administrative_action' | 'security_control' | 'system' | 'unknown';
export type SocOutcome = 'success' | 'failure' | 'denied' | 'blocked' | 'unknown';
export type SocAlertStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive';
export type SocIndicatorType = 'ip' | 'domain' | 'username';

export interface SocLogSource { id: number; name: string; description: string | null; source_type: 'simulator' | 'jsonl' | 'csv' | 'access_log' | 'auth_log' | 'key_value'; parser_type: string; enabled: boolean; event_count: number; last_ingested_at: string | null; created_at: string; updated_at: string; }
export interface SocLogImport { id: number; source_id: number; filename: string | null; file_hash: string | null; total_lines: number; accepted_events: number; rejected_events: number; status: 'pending' | 'processing' | 'completed' | 'failed'; error_summary: string | null; created_at: string; completed_at: string | null; }
export interface SocEvent { id: number; source_id: number; import_id: number | null; event_time: string; received_at: string; event_type: SocEventType; action: string | null; outcome: SocOutcome | null; severity: SocSeverity; source_ip: string | null; destination_ip: string | null; username: string | null; http_method: string | null; request_path: string | null; status_code: number | null; user_agent: string | null; message: string | null; normalized_json: Record<string, unknown>; raw_event_hash: string; raw_preview_redacted: string | null; created_at: string; }
export interface SocPage<T> { items: T[]; total: number; page: number; page_size: number; }
export interface SocDetectionRule { id: number; rule_code: string; name: string; description: string; rule_type: string; enabled: boolean; severity: SocSeverity; confidence: SocConfidence; window_seconds: number; threshold: number; group_by: string; conditions_json: Record<string, unknown>; remediation: string; is_default: boolean; created_at: string; updated_at: string; }
export interface SocAlert { id: number; rule_id: number; rule_code: string; rule_name: string; title: string; description: string; severity: SocSeverity; confidence: SocConfidence; status: SocAlertStatus; first_seen: string; last_seen: string; event_count: number; correlation_key: string; source_ip: string | null; username: string | null; evidence_summary: string; fingerprint: string; analyst_notes: string | null; created_at: string; updated_at: string; }
export interface SocAlertDetail extends SocAlert { events: SocEvent[]; enrichments: SocThreatIntelResult[]; blocklist_entries: Array<{ id: number; indicator_type: string; indicator_value: string; status: string; reason: string }>; }
export interface SocThreatIntelResult { id: number; alert_id: number | null; indicator_type: SocIndicatorType; indicator_value: string; reputation: 'unknown' | 'benign' | 'suspicious' | 'malicious'; confidence: SocConfidence; tags_json: string[]; source_name: 'local_mock_intelligence'; explanation: string; created_at: string; disclaimer: string; }
export interface SocBlocklistEntry { id: number; indicator_type: SocIndicatorType; indicator_value: string; reason: string; source_alert_id: number | null; status: 'active' | 'expired' | 'removed'; expires_at: string | null; created_at: string; updated_at: string; disclaimer: string; }
export interface SocReport { id: number; title: string; report_type: string; html_content: string; summary_json: Record<string, unknown>; created_at: string; }
export interface SocActivity { id: number; action: string; message: string; entity_type: string; entity_id: number | null; created_at: string; }
export interface SocOverview { total_events: number; events_last_24_hours: number; open_alerts: number; high_alerts: number; critical_alerts: number; total_sources: number; enabled_sources: number; active_rules: number; active_blocklist_entries: number; events_by_type: Record<string, number>; alerts_by_severity: Record<string, number>; alerts_by_status: Record<string, number>; top_source_ips: Array<{ value: string; count: number }>; top_usernames: Array<{ value: string; count: number }>; recent_alerts: SocAlert[]; recent_imports: SocLogImport[]; recent_activity: SocActivity[]; }
export interface SocSimulatorResult { events_created: number; events_skipped_as_duplicates: number; source_id: number; start_time: string; end_time: string; disclaimer: string; }
export interface SocDetectionRunResult { rules_processed: number; events_processed: number; alerts_created: number; alerts_updated: number; duplicate_alerts_skipped: number; disclaimer: string; }

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
  api_findings: number;
  high_risk_api_findings: number;
  owasp_categories_with_indicators: number;
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

export interface JwtAnalysis {
  id: number;
  assessment_id: number | null;
  token_fingerprint: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  algorithm: string | null;
  issuer: string | null;
  audience: string[];
  issued_at: string | null;
  expires_at: string | null;
  not_before: string | null;
  expiration_status: 'missing' | 'expired' | 'valid' | 'long_lived' | 'unknown';
  risk_score: number;
  findings: Array<{ code: string; title: string; severity: string; detail: string }>;
  disclaimer: string;
  created_at: string;
}

export interface ApiFinding {
  id: number;
  assessment_id: number;
  endpoint_id: number | null;
  title: string;
  owasp_category: string | null;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  source: 'openapi' | 'postman' | 'jwt' | 'response_schema' | 'inventory' | 'authorization_matrix' | 'object_level_review' | 'function_level_review' | 'property_level_review' | 'business_flow';
  fingerprint: string;
  created_at: string;
  updated_at: string;
}

export interface ApiOwaspCoverage {
  id: number;
  assessment_id: number;
  category_id: string;
  category_title: string;
  status: 'covered' | 'partial' | 'not_observed' | 'not_applicable';
  finding_count: number;
  evidence_summary: string;
  created_at: string;
  updated_at: string;
  related_findings: ApiFinding[];
}

export interface ResponseExposureItem {
  endpoint_id: number | null;
  method: string;
  path: string;
  status_code: string | null;
  field_path: string;
  exposure_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
  remediation: string;
}

export interface AnalyzeAssessmentResult {
  assessment_id: number;
  findings_created: number;
  findings_total: number;
  high_or_critical_findings: number;
  coverage_categories: number;
}

export interface ApiReport {
  id: number;
  assessment_id: number;
  title: string;
  executive_summary: string;
  html_content: string;
  summary: Record<string, unknown>;
  created_at: string;
}

export type ApiPrivilegeLevel = 'public' | 'user' | 'privileged' | 'admin' | 'service';
export type ApiExpectedAccess = 'allow' | 'deny' | 'conditional' | 'unknown';
export type ApiObjectScope = 'own' | 'assigned' | 'tenant' | 'organization' | 'global' | 'unknown';

export interface ApiRole {
  id: number;
  assessment_id: number;
  name: string;
  description: string | null;
  privilege_level: ApiPrivilegeLevel;
  created_at: string;
  updated_at: string;
}

export interface ApiIdentity {
  id: number;
  assessment_id: number;
  label: string;
  role_id: number | null;
  identity_type: 'anonymous' | 'user' | 'admin' | 'service_account' | 'custom';
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuthorizationMatrixEntry {
  id: number;
  assessment_id: number;
  endpoint_id: number;
  role_id: number;
  expected_access: ApiExpectedAccess;
  object_scope: ApiObjectScope;
  expected_conditions: Record<string, unknown> | null;
  analyst_notes: string | null;
  review_status: 'not_reviewed' | 'reviewed' | 'requires_validation';
  created_at: string;
  updated_at: string;
}

export interface AuthorizationReview {
  id: number;
  assessment_id: number;
  endpoint_id: number;
  matrix_entry_id: number | null;
  review_type: 'object_level' | 'function_level' | 'property_level';
  expected_behavior: string;
  observed_metadata: string;
  risk_indicator: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  manual_validation_required: boolean;
  analyst_decision: 'open' | 'accepted' | 'rejected' | 'needs_testing';
  notes: string | null;
  validation_checklist: string[];
  created_at: string;
  updated_at: string;
}

export interface AuthorizationGenerationResult {
  matrix_entries_created: number;
  reviews_created: number;
  unresolved_high_risk_reviews: number;
  disclaimer: string;
}

export interface ApiBusinessFlowStep {
  id: number;
  flow_id: number;
  step_order: number;
  endpoint_id: number | null;
  action_name: string;
  expected_actor_role: string | null;
  prerequisite_description: string | null;
  expected_state_before: string | null;
  expected_state_after: string | null;
  sensitive_operation: boolean;
  created_at: string;
  updated_at: string;
}

export interface ApiBusinessFlowRisk {
  id: number;
  flow_id: number;
  assessment_id?: number;
  step_id: number | null;
  risk_type: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  description: string;
  evidence_summary: string;
  remediation: string;
  manual_validation_required: boolean;
  status: 'open' | 'accepted' | 'resolved';
  owasp_category: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApiBusinessFlow {
  id: number;
  assessment_id: number;
  name: string;
  description: string;
  business_goal: string | null;
  actor_roles: string[];
  status: 'draft' | 'reviewed' | 'approved';
  risk_score: number;
  steps: ApiBusinessFlowStep[];
  risks: ApiBusinessFlowRisk[];
  created_at: string;
  updated_at: string;
}

export interface ApiBusinessFlowAnalysis {
  flow_id: number;
  risks_created: number;
  risks_total: number;
  high_risk_indicators: number;
  risk_score: number;
  disclaimer: string;
}
