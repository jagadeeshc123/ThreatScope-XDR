import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowRight, FileJson, Network, Play, ScrollText, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import type { ApiAssessmentDetail, ApiEndpoint, ApiFinding, ApiOwaspCoverage, ApiReport, ResponseExposureItem } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard, SeverityBadge, StatCard, StatusBadge } from '../../components/ui';
import { ApiSourceBadge } from './components/ApiSourceBadge';
import { EndpointTable } from './components/EndpointTable';

type Tab = 'overview' | 'inventory' | 'findings' | 'owasp' | 'exposure' | 'imports' | 'reports';

export function ApiAssessmentDetails() {
  const { assessmentId } = useParams();
  const navigate = useNavigate();
  const numericId = Number(assessmentId);
  const [assessment, setAssessment] = useState<ApiAssessmentDetail | null>(null);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [findings, setFindings] = useState<ApiFinding[]>([]);
  const [coverage, setCoverage] = useState<ApiOwaspCoverage[]>([]);
  const [exposure, setExposure] = useState<ResponseExposureItem[]>([]);
  const [reports, setReports] = useState<ApiReport[]>([]);
  const [tab, setTab] = useState<Tab>('overview');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  const load = useCallback(async () => {
    const [detail, apiEndpoints, apiFindings, apiCoverage, apiExposure, apiReports] = await Promise.all([
      vulnscopeApi.getApiAssessment(numericId),
      vulnscopeApi.listApiEndpoints(numericId).catch(() => []),
      vulnscopeApi.listApiFindings(numericId).catch(() => []),
      vulnscopeApi.getApiOwaspCoverage(numericId).catch(() => []),
      vulnscopeApi.getResponseExposure(numericId).catch(() => []),
      vulnscopeApi.listApiReports(numericId).catch(() => []),
    ]);
    setAssessment(detail);
    setEndpoints(apiEndpoints);
    setFindings(apiFindings);
    setCoverage(apiCoverage);
    setExposure(apiExposure);
    setReports(apiReports);
  }, [numericId]);

  useEffect(() => {
    if (!numericId) return;
    let cancelled = false;
    setLoading(true);
    load().finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [numericId, load]);

  async function remove() {
    if (!assessment || !window.confirm(`Delete API assessment "${assessment.name}"?`)) return;
    await vulnscopeApi.deleteApiAssessment(assessment.id);
    toast.success('API assessment deleted');
    navigate('/api-security');
  }

  async function analyze() {
    setBusy('analyze');
    try {
      const result = await vulnscopeApi.analyzeApiAssessment(numericId);
      toast.success(`Analysis complete: ${result.findings_created} new findings`);
      await load();
      setTab('findings');
    } finally {
      setBusy('');
    }
  }

  async function generateReport() {
    setBusy('report');
    try {
      await vulnscopeApi.generateApiReport(numericId);
      toast.success('API report generated');
      await load();
      setTab('reports');
    } finally {
      setBusy('');
    }
  }

  const filteredFindings = useMemo(() => findings.filter(item => !severityFilter || item.severity === severityFilter), [findings, severityFilter]);
  const severityDistribution = useMemo(() => findings.reduce<Record<string, number>>((acc, item) => ({ ...acc, [item.severity]: (acc[item.severity] || 0) + 1 }), {}), [findings]);

  if (loading) return <PageShell><div className="text-muted-foreground">Loading assessment...</div></PageShell>;
  if (!assessment) return <PageShell><EmptyState title="Assessment unavailable" description="The API assessment could not be loaded." /></PageShell>;

  const tabs: Array<[Tab, string]> = [['overview', 'Overview'], ['inventory', 'Endpoint Inventory'], ['findings', 'Findings'], ['owasp', 'OWASP Coverage'], ['exposure', 'Response Exposure'], ['imports', 'Import Details'], ['reports', 'Reports']];

  return (
    <PageShell>
      <PageHeader
        title={assessment.name}
        subtitle={assessment.description || 'Passive API Security assessment'}
        actions={<>
          <button onClick={() => void analyze()} disabled={busy === 'analyze'} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white hover:bg-indigo-400 disabled:opacity-60"><Play className="h-4 w-4" /> {busy === 'analyze' ? 'Analyzing...' : 'Analyze Assessment'}</button>
          <button onClick={() => void generateReport()} disabled={busy === 'report'} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted disabled:opacity-60"><ScrollText className="h-4 w-4" /> Generate Report</button>
          <Link to={`/api-security/assessments/${assessment.id}/import`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted">Import <FileJson className="h-4 w-4" /></Link>
          <button onClick={() => void remove()} className="inline-flex h-10 items-center gap-2 rounded-md border border-red-400/40 px-4 text-sm font-semibold text-red-200 hover:bg-red-500/10"><Trash2 className="h-4 w-4" /> Delete</button>
        </>}
      />
      <div className="flex flex-wrap gap-2">
        <ApiSourceBadge source={assessment.source_type} />
        <StatusBadge status={assessment.status} />
        {assessment.source_filename && <span className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground">{assessment.source_filename}</span>}
      </div>
      <div className="flex flex-wrap gap-2 border-b border-border">
        {tabs.map(([key, label]) => <button key={key} onClick={() => setTab(key)} className={`px-3 py-2 text-sm font-semibold ${tab === key ? 'border-b-2 border-indigo-300 text-indigo-200' : 'text-muted-foreground hover:text-foreground'}`}>{label}</button>)}
      </div>
      {tab === 'overview' && <>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          <StatCard label="Endpoints" value={assessment.endpoint_count} icon={<Network className="h-5 w-5" />} />
          <StatCard label="Unauthenticated" value={assessment.unauthenticated_endpoint_count} tone="warn" />
          <StatCard label="High-Risk Endpoints" value={assessment.high_risk_endpoint_count} tone="danger" />
          <StatCard label="Findings" value={findings.length} tone="warn" />
          <StatCard label="Risk Score" value={`${assessment.risk_score}/10`} tone="info" />
        </div>
        <SectionCard title="Severity Distribution">{Object.keys(severityDistribution).length ? <div className="grid gap-3 sm:grid-cols-5">{Object.entries(severityDistribution).map(([severity, count]) => <div key={severity} className="rounded-md border border-border bg-background/60 p-4"><SeverityBadge severity={severity} /><div className="mt-2 text-2xl font-semibold">{count}</div></div>)}</div> : <p className="text-sm text-muted-foreground">Run assessment analysis to generate findings.</p>}</SectionCard>
        <SectionCard title="OWASP Summary"><div className="grid gap-3 sm:grid-cols-4">{coverage.map(item => <div key={item.category_id} className="rounded-md border border-border bg-background/60 p-4"><div className="font-semibold">{item.category_id}</div><div className="mt-1 text-sm capitalize text-muted-foreground">{item.status.replaceAll('_', ' ')}</div></div>)}</div></SectionCard>
      </>}
      {tab === 'inventory' && <SectionCard title="Endpoint Inventory" subtitle={`${endpoints.length} records`}>{endpoints.length ? <EndpointTable endpoints={endpoints.slice(0, 15)} /> : <EmptyState title="No endpoints yet" description="Import an OpenAPI or Postman definition to populate inventory." action={<Link to={`/api-security/assessments/${assessment.id}/import`} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white hover:bg-indigo-400">Import definition <ArrowRight className="h-4 w-4" /></Link>} />}{endpoints.length > 15 && <Link to={`/api-security/assessments/${assessment.id}/endpoints`} className="mt-4 inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm font-semibold hover:bg-muted">Open full inventory <ArrowRight className="h-4 w-4" /></Link>}</SectionCard>}
      {tab === 'findings' && <SectionCard title="Findings" subtitle={`${filteredFindings.length} matching`}>
        <label className="mb-4 block max-w-xs text-xs font-semibold text-muted-foreground">Severity<select value={severityFilter} onChange={event => setSeverityFilter(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"><option value="">All</option>{['critical', 'high', 'medium', 'low', 'info'].map(item => <option key={item}>{item}</option>)}</select></label>
        {filteredFindings.length ? <div className="space-y-3">{filteredFindings.map(finding => <article key={finding.id} className="rounded-md border border-border bg-background/60 p-4"><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="text-xs text-muted-foreground">{finding.owasp_category || 'Unmapped'} | {finding.source} | {finding.confidence} confidence</span></div><h3 className="mt-2 font-semibold">{finding.title}</h3><p className="mt-2 text-sm text-muted-foreground">{finding.description}</p><p className="mt-2 text-sm text-muted-foreground"><strong className="text-foreground">Evidence:</strong> {finding.evidence}</p><p className="mt-2 text-sm text-muted-foreground"><strong className="text-foreground">Remediation:</strong> {finding.remediation}</p></article>)}</div> : <EmptyState title="No findings yet" description="Run assessment analysis to generate passive API findings." />}</SectionCard>}
      {tab === 'owasp' && <SectionCard title="OWASP API Security Top 10 Coverage" subtitle="Conservative static mapping; manual validation notes are included."><div className="space-y-3">{coverage.map(item => <article key={item.category_id} className="rounded-md border border-border bg-background/60 p-4"><div className="flex flex-wrap items-center justify-between gap-3"><h3 className="font-semibold">{item.category_id} {item.category_title}</h3><span className="rounded-full border border-border px-2.5 py-1 text-xs capitalize">{item.status.replaceAll('_', ' ')}</span></div><p className="mt-2 text-sm text-muted-foreground">{item.evidence_summary}</p><p className="mt-2 text-xs text-indigo-200">{item.finding_count} related finding indicators</p></article>)}</div></SectionCard>}
      {tab === 'exposure' && <SectionCard title="Response Exposure" subtitle="Field names and schema metadata only; no requests executed.">{exposure.length ? <div className="overflow-x-auto"><table className="w-full min-w-[900px] text-left text-sm"><thead className="border-b border-border text-xs text-muted-foreground"><tr><th className="py-3 pr-4">Endpoint</th><th className="py-3 pr-4">Status</th><th className="py-3 pr-4">Field</th><th className="py-3 pr-4">Type</th><th className="py-3 pr-4">Severity</th><th className="py-3">Remediation</th></tr></thead><tbody className="divide-y divide-border">{exposure.map((item, index) => <tr key={`${item.method}-${item.path}-${item.field_path}-${index}`}><td className="py-4 pr-4 font-mono text-xs">{item.method} {item.path}</td><td className="py-4 pr-4">{item.status_code || '-'}</td><td className="py-4 pr-4">{item.field_path}</td><td className="py-4 pr-4">{item.exposure_type}</td><td className="py-4 pr-4"><SeverityBadge severity={item.severity} /></td><td className="py-4 text-xs text-muted-foreground">{item.remediation}</td></tr>)}</tbody></table></div> : <EmptyState title="No response exposure indicators" description="No sensitive response schema fields were observed in imported metadata." />}</SectionCard>}
      {tab === 'imports' && <SectionCard title="Import Details">{assessment.artifacts.length ? <div className="space-y-4">{assessment.artifacts.map(artifact => <pre key={artifact.id} className="overflow-auto rounded-md border border-border bg-background/70 p-4 text-xs text-muted-foreground">{JSON.stringify({ filename: artifact.filename, artifact_type: artifact.artifact_type, parsed_summary: artifact.parsed_summary, created_at: artifact.created_at }, null, 2)}</pre>)}</div> : <p className="text-sm text-muted-foreground">No import artifacts have been recorded.</p>}</SectionCard>}
      {tab === 'reports' && <SectionCard title="Reports">{reports.length ? <div className="space-y-3">{reports.map(report => <article key={report.id} className="rounded-md border border-border bg-background/60 p-4"><h3 className="font-semibold">{report.title}</h3><p className="mt-2 text-sm text-muted-foreground">{report.executive_summary}</p><div className="mt-3 flex flex-wrap gap-2"><Link to={`/api-security/reports/${report.id}`} className="text-sm font-semibold text-indigo-200 hover:underline">View record</Link><button onClick={() => void vulnscopeApi.downloadApiReport(report.id)} className="text-sm font-semibold text-indigo-200 hover:underline">Download HTML</button></div></article>)}</div> : <EmptyState title="No reports yet" description="Generate an API Security report after analysis." />}</SectionCard>}
    </PageShell>
  );
}
