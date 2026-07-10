import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowRight, FileJson, Network, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import type { ApiAssessmentDetail, ApiEndpoint, ApiSecuritySummary } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard, StatCard, StatusBadge } from '../../components/ui';
import { ApiSourceBadge } from './components/ApiSourceBadge';
import { EndpointTable } from './components/EndpointTable';

export function ApiAssessmentDetails() {
  const { assessmentId } = useParams();
  const navigate = useNavigate();
  const numericId = Number(assessmentId);
  const [assessment, setAssessment] = useState<ApiAssessmentDetail | null>(null);
  const [summary, setSummary] = useState<ApiSecuritySummary | null>(null);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [tab, setTab] = useState<'overview' | 'inventory' | 'imports'>('overview');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!numericId) return;
    let cancelled = false;
    Promise.all([
      vulnscopeApi.getApiAssessment(numericId),
      vulnscopeApi.getApiSecuritySummary(numericId).catch(() => null),
      vulnscopeApi.listApiEndpoints(numericId).catch(() => []),
    ])
      .then(([detail, apiSummary, apiEndpoints]) => {
        if (cancelled) return;
        setAssessment(detail);
        setSummary(apiSummary);
        setEndpoints(apiEndpoints);
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [numericId]);

  async function remove() {
    if (!assessment || !window.confirm(`Delete API assessment "${assessment.name}"?`)) return;
    await vulnscopeApi.deleteApiAssessment(assessment.id);
    toast.success('API assessment deleted');
    navigate('/api-security');
  }

  if (loading) return <PageShell><div className="text-muted-foreground">Loading assessment...</div></PageShell>;
  if (!assessment) return <PageShell><EmptyState title="Assessment unavailable" description="The API assessment could not be loaded." /></PageShell>;

  return (
    <PageShell>
      <PageHeader
        title={assessment.name}
        subtitle={assessment.description || 'Passive API Security assessment'}
        actions={
          <>
            <Link to={`/api-security/assessments/${assessment.id}/import`} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white hover:bg-indigo-400">Import <FileJson className="h-4 w-4" /></Link>
            <button onClick={() => void remove()} className="inline-flex h-10 items-center gap-2 rounded-md border border-red-400/40 px-4 text-sm font-semibold text-red-200 hover:bg-red-500/10"><Trash2 className="h-4 w-4" /> Delete</button>
          </>
        }
      />
      <div className="flex flex-wrap gap-2">
        <ApiSourceBadge source={assessment.source_type} />
        <StatusBadge status={assessment.status} />
        {assessment.source_filename && <span className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground">{assessment.source_filename}</span>}
      </div>
      <div className="flex gap-2 border-b border-border">
        {(['overview', 'inventory', 'imports'] as const).map(item => (
          <button key={item} onClick={() => setTab(item)} className={`px-3 py-2 text-sm font-semibold capitalize ${tab === item ? 'border-b-2 border-indigo-300 text-indigo-200' : 'text-muted-foreground hover:text-foreground'}`}>{item === 'imports' ? 'Import Details' : item}</button>
        ))}
      </div>
      {tab === 'overview' && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Endpoints" value={assessment.endpoint_count} icon={<Network className="h-5 w-5" />} />
            <StatCard label="Unauthenticated" value={assessment.unauthenticated_endpoint_count} tone="warn" />
            <StatCard label="High Risk" value={assessment.high_risk_endpoint_count} tone="danger" />
            <StatCard label="Risk Score" value={`${assessment.risk_score}/10`} tone="info" />
          </div>
          <SectionCard title="Risk Distribution">
            {summary ? <div className="grid gap-3 sm:grid-cols-4">{Object.entries(summary.risk_distribution).map(([risk, count]) => <div key={risk} className="rounded-md border border-border bg-background/60 p-4"><div className="text-sm capitalize text-muted-foreground">{risk}</div><div className="mt-2 text-2xl font-semibold">{count}</div></div>)}</div> : <p className="text-sm text-muted-foreground">No endpoint inventory imported yet.</p>}
          </SectionCard>
        </>
      )}
      {tab === 'inventory' && (
        <SectionCard title="Endpoint Inventory" subtitle={`${endpoints.length} records`}>
          {endpoints.length ? <EndpointTable endpoints={endpoints.slice(0, 15)} /> : <EmptyState title="No endpoints yet" description="Import an OpenAPI or Postman definition to populate inventory." action={<Link to={`/api-security/assessments/${assessment.id}/import`} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white hover:bg-indigo-400">Import definition <ArrowRight className="h-4 w-4" /></Link>} />}
          {endpoints.length > 15 && <Link to={`/api-security/assessments/${assessment.id}/endpoints`} className="mt-4 inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm font-semibold hover:bg-muted">Open full inventory <ArrowRight className="h-4 w-4" /></Link>}
        </SectionCard>
      )}
      {tab === 'imports' && (
        <SectionCard title="Import Details">
          {assessment.artifacts.length ? (
            <div className="space-y-4">
              {assessment.artifacts.map(artifact => <pre key={artifact.id} className="overflow-auto rounded-md border border-border bg-background/70 p-4 text-xs text-muted-foreground">{JSON.stringify({ filename: artifact.filename, artifact_type: artifact.artifact_type, parsed_summary: artifact.parsed_summary, created_at: artifact.created_at }, null, 2)}</pre>)}
            </div>
          ) : <p className="text-sm text-muted-foreground">No import artifacts have been recorded.</p>}
        </SectionCard>
      )}
    </PageShell>
  );
}

