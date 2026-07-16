import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowRight, FileText, Network, Radar, Search, Shield, ShieldAlert, Target } from 'lucide-react';
import type { SearchResults } from '../types';
import { vulnscopeApi } from '../api/vulnscope';
import { EmptyState, PageHeader, PageShell } from '../components/ui';

export function SearchResultsPage() {
  const [searchParams] = useSearchParams();
  const query = searchParams.get('q')?.trim() || '';
  const [results, setResults] = useState<SearchResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!query) {
      setResults(null);
      setError(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);
    vulnscopeApi.search(query)
      .then(data => { if (!cancelled) setResults(data); })
      .catch(() => { if (!cancelled) setError('Search could not reach the VulnScope backend.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [query]);

  const totalResults = results ? results.targets.length + results.scans.length + results.findings.length + results.reports.length + results.api_assessments.length + results.api_endpoints.length + results.api_findings.length + results.jwt_analyses.length + results.api_reports.length + results.api_roles.length + results.authorization_reviews.length + results.api_business_flows.length + results.api_business_flow_risks.length + results.soc_events.length + results.soc_alerts.length + results.soc_rules.length + results.soc_reports.length + results.soc_blocklist_entries.length + results.document_analyses.length + results.document_findings.length + results.document_indicators.length + results.document_reports.length + results.phishing_analyses.length + results.phishing_findings.length + results.phishing_indicators.length + results.phishing_watchlist_entries.length + results.phishing_reports.length + results.unified_entities.length + results.correlation_matches.length + results.incident_cases.length + results.incident_evidence.length + results.incident_reports.length + results.governance_risks.length + results.governance_frameworks.length + results.governance_controls.length + results.governance_mappings.length + results.governance_treatments.length + results.governance_exceptions.length + results.governance_evidence_packages.length + results.governance_reviews.length + results.governance_reports.length + results.threat_indicators.length + results.threat_sources.length + results.threat_watchlists.length + results.threat_campaigns.length + results.threat_matches.length + results.threat_reports.length + results.operations.length : 0;

  return (
    <PageShell className="max-w-5xl">
      <PageHeader title={query ? `Search results for "${query}"` : 'Search VulnScope'} subtitle={query && !loading && !error ? `${totalResults} matching records across Web Exposure, API Security, and SOC Monitor.` : 'Search the current ThreatScope workspace.'} />
      {!query && <EmptyState title="Enter a search term" description="Use the search field in the top bar to find targets, scans, findings, and reports." icon={<Search className="h-8 w-8" />} />}
      {loading && <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">Searching backend records...</div>}
      {!loading && error && <EmptyState title="Search unavailable" description={error} />}
      {!loading && !error && query && totalResults === 0 && <EmptyState title="No results found" description="Try a target name, scan status, finding title, severity, URL, or report title." icon={<Search className="h-8 w-8" />} />}
      {!loading && !error && totalResults > 0 && results && (
        <div className="space-y-8">
          <ResultGroup title="Targets" icon={<Target className="h-5 w-5 text-blue-400" />} count={results.targets.length}>
            {results.targets.map(target => <ResultLink key={target.id} to={`/targets?highlight=${target.id}`} title={target.name} detail={target.base_url} />)}
          </ResultGroup>
          <ResultGroup title="Scans" icon={<Activity className="h-5 w-5 text-emerald-400" />} count={results.scans.length}>
            {results.scans.map(scan => <ResultLink key={scan.id} to={`/scans?highlight=${scan.id}`} title={`Scan #${scan.id} - ${scan.profile}`} detail={`Status: ${scan.status} | Risk score: ${scan.risk_score}`} />)}
          </ResultGroup>
          <ResultGroup title="Findings" icon={<AlertTriangle className="h-5 w-5 text-amber-300" />} count={results.findings.length}>
            {results.findings.map(finding => <ResultLink key={finding.id} to={`/scans?highlight=${finding.scan_id}&tab=findings`} title={`${finding.severity.toUpperCase()} - ${finding.title}`} detail={finding.affected_url} />)}
          </ResultGroup>
          <ResultGroup title="Reports" icon={<FileText className="h-5 w-5 text-fuchsia-300" />} count={results.reports.length}>
            {results.reports.map(report => <ResultLink key={report.id} to={`/reports?reportId=${report.id}`} title={report.title} detail={`Generated ${new Date(report.created_at).toLocaleString()}`} />)}
          </ResultGroup>
          <ResultGroup title="API Assessments" icon={<Network className="h-5 w-5 text-indigo-300" />} count={results.api_assessments.length}>
            {results.api_assessments.map(assessment => <ResultLink key={assessment.id} to={`/api-security/assessments/${assessment.id}`} title={assessment.name} detail={`${assessment.source_type.toUpperCase()} | ${assessment.endpoint_count} endpoints | ${assessment.status}`} />)}
          </ResultGroup>
          <ResultGroup title="API Endpoints" icon={<Network className="h-5 w-5 text-violet-300" />} count={results.api_endpoints.length}>
            {results.api_endpoints.map(endpoint => <ResultLink key={endpoint.id} to={`/api-security/assessments/${endpoint.assessment_id}/endpoints?q=${encodeURIComponent(endpoint.path)}`} title={`${endpoint.method} ${endpoint.path}`} detail={`${endpoint.preliminary_risk_level.toUpperCase()} | ${endpoint.auth_required ? 'Auth required' : 'No auth declared'}`} />)}
          </ResultGroup>
          <ResultGroup title="API Findings" icon={<AlertTriangle className="h-5 w-5 text-red-300" />} count={results.api_findings.length}>
            {results.api_findings.map(finding => <ResultLink key={finding.id} to={`/api-security/assessments/${finding.assessment_id}`} title={`${finding.severity.toUpperCase()} - ${finding.title}`} detail={`${finding.owasp_category || 'Unmapped'} | ${finding.source}`} />)}
          </ResultGroup>
          <ResultGroup title="JWT Analyses" icon={<Network className="h-5 w-5 text-cyan-300" />} count={results.jwt_analyses.length}>
            {results.jwt_analyses.map(analysis => <ResultLink key={analysis.id} to={`/api-security/jwt/${analysis.id}`} title={`JWT ${analysis.token_fingerprint.slice(0, 12)}`} detail={`${analysis.algorithm || 'No alg'} | risk ${analysis.risk_score}/10 | ${analysis.expiration_status}`} />)}
          </ResultGroup>
          <ResultGroup title="API Reports" icon={<FileText className="h-5 w-5 text-indigo-300" />} count={results.api_reports.length}>
            {results.api_reports.map(report => <ResultLink key={report.id} to={`/api-security/assessments/${report.assessment_id}`} title={report.title} detail={`Generated ${new Date(report.created_at).toLocaleString()}`} />)}
          </ResultGroup>
          <ResultGroup title="API Roles" icon={<Shield className="h-5 w-5 text-indigo-300" />} count={results.api_roles.length}>
            {results.api_roles.map(role => <ResultLink key={role.id} to={`/api-security/assessments/${role.assessment_id}/authorization`} title={role.name} detail={`${role.privilege_level} privilege | ${role.description || 'No description'}`} />)}
          </ResultGroup>
          <ResultGroup title="Authorization Reviews" icon={<ShieldAlert className="h-5 w-5 text-amber-300" />} count={results.authorization_reviews.length}>
            {results.authorization_reviews.map(review => <ResultLink key={review.id} to={`/api-security/assessments/${review.assessment_id}/authorization-reviews`} title={review.risk_indicator} detail={`${review.review_type.replaceAll('_', ' ')} | ${review.severity} | ${review.analyst_decision}`} />)}
          </ResultGroup>
          <ResultGroup title="Business Flows" icon={<Network className="h-5 w-5 text-cyan-300" />} count={results.api_business_flows.length}>
            {results.api_business_flows.map(flow => <ResultLink key={flow.id} to={`/api-security/business-flows/${flow.id}`} title={flow.name} detail={`${flow.status} | risk ${flow.risk_score}/100`} />)}
          </ResultGroup>
          <ResultGroup title="Business Flow Risks" icon={<AlertTriangle className="h-5 w-5 text-orange-300" />} count={results.api_business_flow_risks.length}>
            {results.api_business_flow_risks.map(risk => <ResultLink key={risk.id} to={`/api-security/business-flows/${risk.flow_id}`} title={risk.title} detail={`${risk.severity} | ${risk.status} | ${risk.risk_type.replaceAll('_', ' ')}`} />)}
          </ResultGroup>
          <ResultGroup title="SOC Events" icon={<Radar className="h-5 w-5 text-cyan-300" />} count={results.soc_events.length}>
            {results.soc_events.map(event => <ResultLink key={event.id} to={`/soc/events/${event.id}`} title={`${event.event_type.replaceAll('_', ' ')} · ${event.severity}`} detail={`${event.source_ip || event.username || 'Unattributed'} · ${event.snippet}`} />)}
          </ResultGroup>
          <ResultGroup title="SOC Alerts" icon={<ShieldAlert className="h-5 w-5 text-red-300" />} count={results.soc_alerts.length}>
            {results.soc_alerts.map(alert => <ResultLink key={alert.id} to={`/soc/alerts/${alert.id}`} title={`${alert.severity.toUpperCase()} · ${alert.title}`} detail={`${alert.status} · ${alert.snippet}`} />)}
          </ResultGroup>
          <ResultGroup title="SOC Rules" icon={<Shield className="h-5 w-5 text-indigo-300" />} count={results.soc_rules.length}>
            {results.soc_rules.map(rule => <ResultLink key={rule.id} to="/soc/rules" title={`${rule.rule_code} · ${rule.name}`} detail={`${rule.severity} · ${rule.enabled ? 'enabled' : 'disabled'}`} />)}
          </ResultGroup>
          <ResultGroup title="SOC Reports" icon={<FileText className="h-5 w-5 text-cyan-300" />} count={results.soc_reports.length}>
            {results.soc_reports.map(report => <ResultLink key={report.id} to={`/soc/reports/${report.id}`} title={report.title} detail={`Generated ${new Date(report.created_at).toLocaleString()}`} />)}
          </ResultGroup>
          <ResultGroup title="Simulated Blocklist" icon={<Shield className="h-5 w-5 text-amber-300" />} count={results.soc_blocklist_entries.length}>
            {results.soc_blocklist_entries.map(entry => <ResultLink key={entry.id} to="/soc/blocklist" title={`${entry.indicator_type}: ${entry.indicator_value}`} detail={`${entry.status} · ${entry.reason}`} />)}
          </ResultGroup>
          <ResultGroup title="Document Analyses" icon={<FileText className="h-5 w-5 text-cyan-300" />} count={results.document_analyses.length}>{results.document_analyses.map(item=><ResultLink key={item.id} to={`/document-threats/analyses/${item.id}`} title={item.filename_sanitized} detail={`${item.classification.replaceAll('_',' ')} · risk ${item.risk_score}/100 · ${item.file_hash.slice(0,16)}…`}/>)}</ResultGroup>
          <ResultGroup title="Document Findings" icon={<ShieldAlert className="h-5 w-5 text-orange-300" />} count={results.document_findings.length}>{results.document_findings.map(item=><ResultLink key={item.id} to={`/document-threats/analyses/${item.analysis_id}`} title={`${item.rule_code} · ${item.title}`} detail={`${item.severity} · ${item.snippet}`}/>)}</ResultGroup>
          <ResultGroup title="Document Indicators" icon={<Search className="h-5 w-5 text-indigo-300" />} count={results.document_indicators.length}>{results.document_indicators.map(item=><ResultLink key={item.id} to={`/document-threats/analyses/${item.analysis_id}`} title={`${item.indicator_type}: ${item.display_value_redacted}`} detail={item.snippet}/>)}</ResultGroup>
          <ResultGroup title="Document Reports" icon={<FileText className="h-5 w-5 text-fuchsia-300" />} count={results.document_reports.length}>{results.document_reports.map(item=><ResultLink key={item.id} to={`/document-threats/reports/${item.id}`} title={item.title} detail={`Generated ${new Date(item.created_at).toLocaleString()}`}/>)}</ResultGroup>
          <ResultGroup title="Phishing Analyses" icon={<ShieldAlert className="h-5 w-5 text-cyan-300" />} count={results.phishing_analyses.length}>{results.phishing_analyses.map(x=><ResultLink key={x.id} to={`/phishing-defense/analyses/${x.id}`} title={x.subject_redacted||x.sender_address_redacted||`Analysis ${x.id}`} detail={`${x.classification} · risk ${x.final_risk_score}/100`}/>)}</ResultGroup>
          <ResultGroup title="Phishing Findings" icon={<AlertTriangle className="h-5 w-5 text-orange-300" />} count={results.phishing_findings.length}>{results.phishing_findings.map(x=><ResultLink key={x.id} to={`/phishing-defense/analyses/${x.analysis_id}`} title={`${x.rule_code} · ${x.title}`} detail={`${x.severity} · ${x.snippet}`}/>)}</ResultGroup>
          <ResultGroup title="Phishing Indicators" icon={<Search className="h-5 w-5 text-indigo-300" />} count={results.phishing_indicators.length}>{results.phishing_indicators.map(x=><ResultLink key={x.id} to={`/phishing-defense/analyses/${x.analysis_id}`} title={`${x.indicator_type}: ${x.display_value_redacted}`} detail={x.snippet}/>)}</ResultGroup>
          <ResultGroup title="Phishing Watchlist" icon={<Shield className="h-5 w-5 text-amber-300" />} count={results.phishing_watchlist_entries.length}>{results.phishing_watchlist_entries.map(x=><ResultLink key={x.id} to="/phishing-defense/watchlist" title={`${x.indicator_type}: ${x.display_value_redacted}`} detail={`${x.status} · ${x.reason}`}/>)}</ResultGroup>
          <ResultGroup title="Phishing Reports" icon={<FileText className="h-5 w-5 text-fuchsia-300" />} count={results.phishing_reports.length}>{results.phishing_reports.map(x=><ResultLink key={x.id} to={`/phishing-defense/reports/${x.id}`} title={x.title} detail={`Generated ${new Date(x.created_at).toLocaleString()}`}/>)}</ResultGroup>
          <ResultGroup title="Unified Entities" icon={<Network className="h-5 w-5 text-cyan-300"/>} count={results.unified_entities.length}>{results.unified_entities.map(x=><ResultLink key={x.id} to={`/correlation/entities/${x.id}`} title={`${x.entity_type}: ${x.display_value_redacted}`} detail={`${x.severity} · ${x.risk_score}/100`}/>)}</ResultGroup><ResultGroup title="Correlation Matches" icon={<ShieldAlert className="h-5 w-5 text-orange-300"/>} count={results.correlation_matches.length}>{results.correlation_matches.map(x=><ResultLink key={x.id} to={`/correlation/matches/${x.id}`} title={`${x.rule_code} · ${x.title}`} detail={`${x.status} · ${x.snippet}`}/>)}</ResultGroup><ResultGroup title="Incident Cases" icon={<FileText className="h-5 w-5 text-red-300"/>} count={results.incident_cases.length}>{results.incident_cases.map(x=><ResultLink key={x.id} to={`/correlation/cases/${x.id}`} title={`${x.case_key} · ${x.title}`} detail={`${x.priority} · ${x.status}`}/>)}</ResultGroup><ResultGroup title="Incident Reports" icon={<FileText className="h-5 w-5 text-fuchsia-300"/>} count={results.incident_reports.length}>{results.incident_reports.map(x=><ResultLink key={x.id} to={`/correlation/reports/${x.id}`} title={x.title} detail={`Case ${x.case_id}`}/>)}</ResultGroup>
          <ResultGroup title="Governance Risks" icon={<ShieldAlert className="h-5 w-5 text-red-300"/>} count={results.governance_risks.length}>{results.governance_risks.map(x=><ResultLink key={x.id} to={`/governance/risks/${x.id}`} title={`${x.risk_key} · ${x.title}`} detail={`${x.severity} · ${x.status}`}/>)}</ResultGroup><ResultGroup title="Governance Frameworks" icon={<Shield className="h-5 w-5 text-blue-300"/>} count={results.governance_frameworks.length}>{results.governance_frameworks.map(x=><ResultLink key={x.id} to={`/governance/frameworks/${x.id}`} title={x.name} detail={`Version ${x.version} · ${x.enabled?'enabled':'disabled'}`}/>)}</ResultGroup><ResultGroup title="Governance Controls" icon={<Shield className="h-5 w-5 text-emerald-300"/>} count={results.governance_controls.length}>{results.governance_controls.map(x=><ResultLink key={x.id} to={`/governance/frameworks/${x.framework_id}`} title={`${x.control_key} · ${x.title}`} detail={x.summary}/>)}</ResultGroup><ResultGroup title="Control Mappings" icon={<Network className="h-5 w-5 text-amber-300"/>} count={results.governance_mappings.length}>{results.governance_mappings.map(x=><ResultLink key={x.id} to="/governance/mappings" title={`Mapping ${x.id} · ${x.mapping_status}`} detail={x.rationale}/>)}</ResultGroup><ResultGroup title="Risk Treatments" icon={<Activity className="h-5 w-5 text-cyan-300"/>} count={results.governance_treatments.length}>{results.governance_treatments.map(x=><ResultLink key={x.id} to="/governance/treatments" title={x.title} detail={`${x.strategy} · ${x.status}`}/>)}</ResultGroup><ResultGroup title="Risk Exceptions" icon={<AlertTriangle className="h-5 w-5 text-orange-300"/>} count={results.governance_exceptions.length}>{results.governance_exceptions.map(x=><ResultLink key={x.id} to="/governance/exceptions" title={x.exception_key} detail={x.status}/>)}</ResultGroup><ResultGroup title="Evidence Packages" icon={<FileText className="h-5 w-5 text-indigo-300"/>} count={results.governance_evidence_packages.length}>{results.governance_evidence_packages.map(x=><ResultLink key={x.id} to={`/governance/evidence/${x.id}`} title={`${x.package_key} · ${x.title}`} detail={x.status}/>)}</ResultGroup><ResultGroup title="Governance Reviews" icon={<Activity className="h-5 w-5 text-blue-300"/>} count={results.governance_reviews.length}>{results.governance_reviews.map(x=><ResultLink key={x.id} to={`/governance/reviews/${x.id}`} title={`${x.review_key} · ${x.title}`} detail={`${x.review_type} · ${x.status}`}/>)}</ResultGroup><ResultGroup title="Governance Reports" icon={<FileText className="h-5 w-5 text-fuchsia-300"/>} count={results.governance_reports.length}>{results.governance_reports.map(x=><ResultLink key={x.id} to={`/governance/reports/${x.id}`} title={x.title} detail={x.report_type}/>)}</ResultGroup>
          <ResultGroup title="Operations" icon={<Activity className="h-5 w-5 text-emerald-300"/>} count={results.operations.length}>{results.operations.map(x=><ResultLink key={`${x.kind}-${x.id}`} to={x.internal_path} title={`${x.kind} · ${x.title}`} detail={x.status}/>)}</ResultGroup>
          <ResultGroup title="Threat Indicators" icon={<ShieldAlert className="h-5 w-5 text-orange-300"/>} count={results.threat_indicators.length}>{results.threat_indicators.map(x=><ResultLink key={x.id} to={`/threat-intelligence/indicators/${x.id}`} title={`${x.indicator_type}: ${x.display_value}`} detail={`${x.severity} · confidence ${x.confidence}%`}/>)}</ResultGroup>
          <ResultGroup title="Threat Sources" icon={<Radar className="h-5 w-5 text-cyan-300"/>} count={results.threat_sources.length}>{results.threat_sources.map(x=><ResultLink key={x.id} to="/threat-intelligence/sources" title={x.name} detail={`${x.source_type} · reliability ${x.reliability}%`}/>)}</ResultGroup>
          <ResultGroup title="IOC Watchlists" icon={<Shield className="h-5 w-5 text-blue-300"/>} count={results.threat_watchlists.length}>{results.threat_watchlists.map(x=><ResultLink key={x.id} to={`/threat-intelligence/watchlists/${x.id}`} title={x.name} detail={x.enabled?'enabled':'disabled'}/>)}</ResultGroup>
          <ResultGroup title="Threat Campaigns" icon={<Network className="h-5 w-5 text-violet-300"/>} count={results.threat_campaigns.length}>{results.threat_campaigns.map(x=><ResultLink key={x.id} to={`/threat-intelligence/campaigns/${x.id}`} title={x.name} detail={`${x.severity} · confidence ${x.confidence}%`}/>)}</ResultGroup>
          <ResultGroup title="IOC Matches" icon={<Activity className="h-5 w-5 text-red-300"/>} count={results.threat_matches.length}>{results.threat_matches.map(x=><ResultLink key={x.id} to={`/threat-intelligence/matches/${x.id}`} title={`Match #${x.id} · risk ${x.risk_score}`} detail={`${x.module} · ${x.status}`}/>)}</ResultGroup>
          <ResultGroup title="Threat-intelligence Reports" icon={<FileText className="h-5 w-5 text-fuchsia-300"/>} count={results.threat_reports.length}>{results.threat_reports.map(x=><ResultLink key={x.id} to={`/threat-intelligence/reports/${x.id}`} title={x.title} detail={`${x.report_type} · ${x.defanged?'defanged':'raw'}`}/>)}</ResultGroup>
        </div>
      )}
    </PageShell>
  );
}

function ResultGroup({ title, icon, count, children }: { title: string; icon: React.ReactNode; count: number; children: React.ReactNode }) {
  if (!count) return null;
  return <section className="space-y-3"><h2 className="flex items-center gap-2 border-b border-border pb-2 text-lg font-semibold">{icon}{title} ({count})</h2><div className="grid gap-3">{children}</div></section>;
}

function ResultLink({ to, title, detail }: { to: string; title: string; detail: string }) {
  return <Link to={to} className="group flex items-center justify-between gap-4 rounded-lg border border-border bg-card p-4 transition-colors hover:border-primary"><div className="min-w-0"><div className="font-medium">{title}</div><div className="mt-1 truncate text-sm text-muted-foreground">{detail}</div></div><ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground transition-colors group-hover:text-primary" /></Link>;
}
