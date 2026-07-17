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
  phishing_total_analyses: number;
  phishing_suspicious_high_risk: number;
  phishing_high_critical_findings: number;
  phishing_active_watchlist_entries: number;
  active_correlation_matches:number;open_incident_cases:number;p1_incident_cases:number;high_critical_incident_cases:number;multi_module_entities:number;
  governance_open_risks:number;governance_high_critical_risks:number;governance_risks_exceeding_appetite:number;governance_control_gaps:number;governance_mappings_awaiting_review:number;governance_active_exceptions:number;
  threat_intel_active_indicators:number;threat_intel_high_risk_matches:number;threat_intel_recent_imports:number;threat_intel_recent_escalations:number;
  detection_active_rules:number;detection_high_risk_matches:number;detection_failed_validations:number;detection_attack_coverage:number;detection_recent_escalations:number;
  severity_distribution: Record<string, number>;
  recent_scans: Scan[];
  highest_risk_targets: Target[];
  operations: {readiness_status:string;degraded_check_count:number;latest_backup_at:string|null;failed_job_count:number;pending_restore_count:number;demo_mode:boolean;release_version:string}|null;
  vulnerability_management: {active_vulnerabilities:number;critical_high_vulnerabilities:number;overdue_vulnerabilities:number;due_within_seven_days:number;unassigned_vulnerabilities:number;recent_resolutions:number;recent_regressions:number}|null;
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
  phishing_analyses: Array<Pick<PhishingAnalysis, 'id' | 'subject_redacted' | 'sender_address_redacted' | 'source_hash' | 'classification' | 'final_risk_score' | 'created_at'>>;
  phishing_findings: Array<Pick<PhishingFinding, 'id' | 'analysis_id' | 'rule_code' | 'title' | 'severity'> & { snippet: string }>;
  phishing_indicators: Array<Pick<PhishingIndicator, 'id' | 'analysis_id' | 'indicator_type' | 'display_value_redacted'> & { snippet: string }>;
  phishing_watchlist_entries: Array<Pick<PhishingWatchlistEntry, 'id' | 'indicator_type' | 'display_value_redacted' | 'status' | 'reason'>>;
  phishing_reports: Array<Pick<PhishingReport, 'id' | 'analysis_id' | 'title' | 'created_at'>>;
  unified_entities:UnifiedEntity[];correlation_matches:CorrelationMatch[];incident_cases:IncidentCase[];incident_evidence:IncidentEvidence[];incident_reports:IncidentReport[];
  governance_risks:GovernanceRisk[];governance_frameworks:GovernanceFramework[];governance_controls:GovernanceControl[];governance_mappings:GovernanceControlMapping[];governance_treatments:RiskTreatmentPlan[];governance_exceptions:RiskException[];governance_evidence_packages:GovernanceEvidencePackage[];governance_reviews:GovernanceReview[];governance_reports:GovernanceReport[];
  threat_indicators:Array<{id:number;indicator_type:string;display_value:string;severity:string;confidence:number;active:boolean}>;
  threat_sources:Array<{id:number;name:string;source_type:string;reliability:number;enabled:boolean}>;
  threat_watchlists:Array<{id:number;name:string;enabled:boolean;system_owned:boolean}>;
  threat_campaigns:Array<{id:number;name:string;severity:string;confidence:number;active:boolean}>;
  threat_matches:Array<{id:number;indicator_id:number;status:string;risk_score:number;module:string}>;
  threat_reports:Array<{id:number;title:string;report_type:string;defanged:boolean;created_at:string}>;
  detection_rules:Array<{id:number;title:string;severity:string;lifecycle_status:string;quality_score:number}>;
  detection_packs:Array<{id:number;name:string;version:string;enabled:boolean;system_owned:boolean}>;
  attack_techniques:Array<{id:number;external_id:string;name:string;tactic:string}>;
  detection_matches:Array<{id:number;rule_id:number;status:string;risk_score:number;severity:string;snippet:string}>;
  detection_executions:Array<{id:number;status:string;mode:string;records_scanned:number;matches_found:number}>;
  detection_suppressions:Array<{id:number;name:string;description:string;enabled:boolean}>;
  detection_reports:Array<{id:number;title:string;report_type:string;created_at:string}>;
  vm_assets:Array<{id:number;name:string;asset_type:string;criticality:string;environment:string;internal_path:string}>;
  vm_vulnerabilities:Array<{id:number;title:string;severity:string;priority_score:number;status:string;internal_path:string}>;
  vm_remediation_plans:Array<{id:number;title:string;status:string;priority:string;internal_path:string}>;
  vm_remediation_tasks:Array<{id:number;title:string;status:string;plan_id:number;internal_path:string}>;
  vm_sla_policies:Array<{id:number;name:string;enabled:boolean;target_days:number;internal_path:string}>;
  vm_risk_acceptances:Array<{id:number;vulnerability_id:number;status:string;residual_risk:string;internal_path:string}>;
  vm_verifications:Array<{id:number;vulnerability_id:number;status:string;verification_type:string;internal_path:string}>;
  vm_remediation_templates:Array<{id:number;title:string;category:string;system_owned:boolean;internal_path:string}>;
  vm_reports:Array<{id:number;title:string;report_type:string;created_at:string;internal_path:string}>;
  operations:Array<{id:number;kind:string;title:string;status:string;internal_path:string}>;
}
export interface UnifiedEntity{id:number;entity_type:string;normalized_value:string;value_hash:string;display_value_redacted:string;risk_score:number;severity:string;confidence:string;observation_count:number;source_module_count:number;first_seen_at:string;last_seen_at:string;watchlist_match:boolean;active:boolean;observations?:EntityObservation[];matches?:CorrelationMatch[];cases?:IncidentCase[]}
export interface EntityObservation{id:number;entity_id:number;source_module:string;source_record_type:string;source_record_id:number;source_internal_route:string|null;title_snapshot:string;evidence_snapshot:string;severity:string;confidence:string;observed_at:string}
export interface CorrelationMatch{id:number;rule_code:string;primary_entity_id:number;title:string;explanation:string;snippet?:string;source_modules:string[];observation_ids:number[];match_score:number;severity:string;confidence:string;status:string;analyst_notes:string|null;updated_at:string}
export interface IncidentEvidence{id:number;case_id:number;source_module:string;title_snapshot:string;evidence_snapshot:string;severity:string;confidence:string;source_internal_route:string|null}
export interface IncidentTimelineEvent{id:number;case_id:number;event_type:string;summary:string;old_value:string|null;new_value:string|null;actor_label:string;created_at:string}
export interface IncidentNote{id:number;case_id:number;note_text:string;author_label:string;created_at:string;updated_at:string}
export interface IncidentActionItem{id:number;case_id:number;title:string;description:string|null;status:string;priority:string;assignee_name:string|null;due_at:string|null;created_at:string;updated_at:string}
export interface IncidentReport{id:number;case_id:number;title:string;html_content:string;summary:Record<string,unknown>;created_at:string}
export interface IncidentCase{id:number;case_key:string;title:string;summary:string;case_type:string;severity:string;priority:string;confidence:string;risk_score:number;status:string;source_module_count:number;evidence_count:number;primary_entity_id:number|null;assignee_name:string|null;tags:string[];resolution_summary:string|null;created_at:string;updated_at:string;closed_at:string|null;evidence?:IncidentEvidence[];timeline?:IncidentTimelineEvent[];notes?:IncidentNote[];actions?:IncidentActionItem[];reports?:IncidentReport[]}
export interface CorrelationOverview{total_entities:number;multi_module_entities:number;high_risk_entities:number;critical_risk_entities:number;active_matches:number;new_matches:number;open_cases:number;p1_cases:number;high_critical_cases:number;cases_awaiting_review:number;resolved_cases:number;active_action_items:number;entities_by_type:Record<string,number>;observations_by_module:Record<string,number>;matches_by_rule:Record<string,number>;cases_by_status:Record<string,number>;recent_matches:CorrelationMatch[];recent_cases:IncidentCase[]}

export type PhishingClassification='low_observed_risk'|'needs_review'|'suspicious'|'high_risk'|'unknown';
export interface PhishingFinding {id:number;analysis_id:number;rule_code:string;title:string;category:string;severity:SocSeverity;confidence:SocConfidence;description:string;evidence_summary:string;technical_impact:string;possible_business_impact:string;remediation:string;manual_validation_required:boolean;fingerprint:string;created_at:string}
export interface PhishingIndicator {id:number;analysis_id:number;indicator_type:string;normalized_value:string;display_value_redacted:string;context:string;severity:SocSeverity;confidence:SocConfidence;source_location:string|null;created_at:string}
export interface PhishingAttachmentMetadata {id:number;analysis_id:number;filename_sanitized:string;extension:string|null;declared_mime_type:string|null;file_size:number|null;sha256:string|null;executable_like:boolean;script_like:boolean;archive_like:boolean;macro_capable:boolean;double_extension:boolean;risk_label:string;evidence_summary:string;created_at:string}
export interface PhishingReport {id:number;analysis_id:number|null;title:string;html_content:string;summary_json:Record<string,unknown>;created_at:string}
export interface PhishingAnalysis {id:number;source_type:'pasted_email'|'eml_file'|'standalone_url';source_hash:string;filename_sanitized:string|null;subject_redacted:string|null;sender_display_redacted:string|null;sender_address_redacted:string|null;reply_to_redacted:string|null;return_path_redacted:string|null;recipient_count:number;url_count:number;attachment_count:number;html_present:boolean;authentication_results_present:boolean;header_summary_json:Record<string,unknown>;feature_summary_json:Record<string,unknown>;bounded_text_character_count:number;model_probability:number|null;model_label:string|null;heuristic_score:number;final_risk_score:number;classification:PhishingClassification;confidence:SocConfidence;analyst_disposition:'unreviewed'|'legitimate'|'suspicious'|'phishing'|'false_positive';analyst_notes:string|null;analysis_status:string;methodology:string;error_summary:string|null;created_at:string;completed_at:string|null;duplicate_existing:boolean}
export interface PhishingAnalysisDetail extends PhishingAnalysis {findings:PhishingFinding[];indicators:PhishingIndicator[];attachments:PhishingAttachmentMetadata[];reports:PhishingReport[]}
export interface PhishingAnalysisPage {items:PhishingAnalysis[];total:number;page:number;page_size:number}
export interface PhishingWatchlistEntry {id:number;indicator_type:string;normalized_value:string;display_value_redacted:string;reason:string;source_analysis_id:number|null;status:'active'|'expired'|'removed';expires_at:string|null;created_at:string;updated_at:string}
export interface PhishingOverview {total_analyses:number;analyses_last_24_hours:number;completed_analyses:number;failed_analyses:number;suspicious_analyses:number;high_risk_analyses:number;total_findings:number;high_critical_findings:number;analyses_with_sender_mismatch:number;analyses_with_suspicious_urls:number;analyses_with_risky_attachments:number;active_watchlist_entries:number;analyses_by_classification:Record<string,number>;findings_by_severity:Record<string,number>;top_finding_categories:Array<{category:string;count:number}>;recent_analyses:PhishingAnalysis[];recent_activities:Array<{id:number;action:string;message:string;created_at:string}>}
export interface PhishingModelInfo {model_type:string;classifier_type:string;tfidf_configuration:string;training_dataset_size:number;class_counts:Record<string,number>;feature_count:number;model_version:string;initialization_timestamp:string;evaluation_method:string;demonstration_metrics:null;limitations:string}

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

export interface GovernanceFramework{id:number;framework_key:string;name:string;version:string;description:string;source_note:string;disclaimer:string;enabled:boolean;control_count:number;created_at:string;updated_at:string;controls?:GovernanceControl[];coverage?:FrameworkCoverage}
export interface GovernanceControl{id:number;framework_id:number;control_key:string;parent_control_key:string|null;title:string;summary:string;control_type:string;sort_order:number;enabled:boolean;created_at:string;updated_at:string}
export interface GovernanceRisk{id:number;risk_key:string;title:string;description:string;origin:string;category:string;owner_name:string|null;status:string;treatment_strategy:string;likelihood:number;impact:number;inherent_score:number;residual_likelihood:number;residual_impact:number;residual_score:number;severity:string;confidence:string;appetite_status:string;due_at:string|null;next_review_at:string|null;source_module_count:number;source_record_count:number;control_mapping_count:number;evidence_count:number;analyst_notes:string|null;resolution_summary:string|null;created_at:string;updated_at:string;closed_at:string|null;sources?:GovernanceRiskSource[];mappings?:GovernanceControlMapping[];treatments?:RiskTreatmentPlan[];exceptions?:RiskException[];evidence_packages?:GovernanceEvidencePackage[]}
export interface GovernanceRiskSource{id:number;risk_id:number;source_module:string;source_record_type:string;source_record_id:number;source_internal_route:string|null;title_snapshot:string;evidence_snapshot:string;source_severity:string;source_confidence:string;observed_at:string;created_at:string}
export interface GovernanceControlMapping{id:number;risk_id:number|null;source_module:string|null;source_record_type:string|null;source_record_id:number|null;control_id:number;mapping_status:string;mapping_basis:string;confidence:string;rationale:string;evidence_summary:string;analyst_notes:string|null;reviewed_at:string|null;created_at:string;updated_at:string;control?:GovernanceControl;framework?:GovernanceFramework;risk?:GovernanceRisk}
export interface RiskTreatmentPlan{id:number;risk_id:number;title:string;description:string;strategy:string;status:string;owner_name:string|null;priority:string;target_date:string|null;expected_residual_likelihood:number|null;expected_residual_impact:number|null;completion_summary:string|null;created_at:string;updated_at:string;completed_at:string|null;risk?:GovernanceRisk}
export interface RiskException{id:number;risk_id:number;exception_key:string;justification:string;approver_name:string|null;status:string;requested_at:string;approved_at:string|null;expires_at:string|null;revoked_at:string|null;review_notes:string|null;created_at:string;updated_at:string;risk?:GovernanceRisk}
export interface GovernanceEvidencePackage{id:number;package_key:string;title:string;description:string;framework_id:number|null;review_id:number|null;status:string;owner_name:string|null;item_count:number;created_at:string;updated_at:string;items?:GovernanceEvidenceItem[]}
export interface GovernanceEvidenceItem{id:number;package_id:number;risk_id:number|null;control_id:number|null;source_module:string;source_record_type:string;source_record_id:number;source_internal_route:string|null;title_snapshot:string;evidence_snapshot:string;evidence_strength:string;observed_at:string;added_at:string;created?:boolean}
export interface GovernanceReview{id:number;review_key:string;title:string;review_type:string;period_start:string;period_end:string;owner_name:string|null;status:string;scope_summary:string;conclusions:string|null;snapshot:Record<string,unknown>|null;created_at:string;updated_at:string;completed_at:string|null}
export interface GovernanceSnapshot{id:number;snapshot_key:string;snapshot_type:string;metric_date:string;metrics:Record<string,number>;source_fingerprint:string;created_at:string;created?:boolean}
export interface GovernanceReport{id:number;report_type:string;risk_id:number|null;framework_id:number|null;package_id:number|null;review_id:number|null;title:string;html_content:string;summary:Record<string,unknown>;created_at:string}
export interface FrameworkCoverage{framework:GovernanceFramework;total_controls:number;assessed_controls:number;supported_controls:number;partial_controls:number;gap_controls:number;not_assessed_controls:number;not_applicable_controls:number;evidence_coverage_percentage:number;controls_by_status:Record<string,number>;top_gaps:Array<{control:GovernanceControl;status:string}>;controls:Array<{control:GovernanceControl;status:string;confirmed_mappings:number;candidate_mappings:number;evidence_items:number;explanation:string}>}
export interface GovernanceOverview{total_risks:number;open_risks:number;high_risks:number;critical_risks:number;risks_exceeding_appetite:number;risks_near_appetite:number;overdue_risks:number;treatments_planned:number;treatments_overdue:number;active_exceptions:number;exceptions_expiring_within_30_days:number;enabled_frameworks:number;total_controls:number;confirmed_mappings:number;candidate_mappings_awaiting_review:number;control_gaps:number;supported_controls:number;evidence_packages:number;reviews_awaiting_approval:number;open_incident_cases:number;p1_cases:number;active_high_risk_correlation_matches:number;risks_by_severity:Record<string,number>;risks_by_status:Record<string,number>;risks_by_category:Record<string,number>;residual_risk_distribution:Array<{risk_key:string;score:number}>;control_coverage_by_framework:FrameworkCoverage[];risk_trend:GovernanceSnapshot[];recent_risks:GovernanceRisk[];upcoming_reviews:GovernanceReview[];disclaimer:string}
export interface GovernancePage<T>{items:T[];total:number;page:number;page_size:number}
export interface GovernanceSyncSummary{source_records_examined:number;candidates_generated:number;risks_created:number;risks_updated:number;risks_reused:number;sources_created:number;sources_reused:number;records_skipped:number;safe_errors:string[];duration_ms:number;per_module_counts:Record<string,number>}
export interface MappingGenerationSummary{risks_evaluated:number;source_records_evaluated:number;rules_evaluated:number;candidates_created:number;candidates_reused:number;candidates_skipped:number;errors:string[];duration_ms:number}
export interface ExceptionExpirationSummary{exceptions_examined:number;newly_expired:number;notifications_created:number;notifications_reused:number;errors:string[];checked_at:string}
