import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowRight, FileText, Network, Search, Target } from 'lucide-react';
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

  const totalResults = results ? results.targets.length + results.scans.length + results.findings.length + results.reports.length + results.api_assessments.length + results.api_endpoints.length : 0;

  return (
    <PageShell className="max-w-5xl">
      <PageHeader title={query ? `Search results for "${query}"` : 'Search VulnScope'} subtitle={query && !loading && !error ? `${totalResults} matching records across Web Exposure and API Security.` : 'Search the current ThreatScope workspace.'} />
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
