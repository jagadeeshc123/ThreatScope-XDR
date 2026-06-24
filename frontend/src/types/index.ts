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
}
