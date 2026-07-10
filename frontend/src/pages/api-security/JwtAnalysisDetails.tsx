import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import type { JwtAnalysis } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard, StatCard } from '../../components/ui';

export function JwtAnalysisDetails() {
  const { analysisId } = useParams();
  const [analysis, setAnalysis] = useState<JwtAnalysis | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const id = Number(analysisId);
    if (!id) return;
    let cancelled = false;
    vulnscopeApi.getJwtAnalysis(id)
      .then(data => { if (!cancelled) setAnalysis(data); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [analysisId]);

  if (loading) return <PageShell><div className="text-muted-foreground">Loading JWT analysis...</div></PageShell>;
  if (!analysis) return <PageShell><EmptyState title="JWT analysis unavailable" description="The selected analysis could not be loaded." /></PageShell>;

  return (
    <PageShell>
      <PageHeader title={`JWT ${analysis.token_fingerprint.slice(0, 12)}`} subtitle={analysis.disclaimer} actions={<Link to="/api-security/jwt" className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted"><ArrowLeft className="h-4 w-4" /> JWT Analyzer</Link>} />
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Risk" value={`${analysis.risk_score}/10`} />
        <StatCard label="Algorithm" value={analysis.algorithm || 'Missing'} />
        <StatCard label="Expiration" value={analysis.expiration_status} />
        <StatCard label="Findings" value={analysis.findings.length} />
      </div>
      <SectionCard title="Detected Risks">
        {analysis.findings.length ? <div className="space-y-3">{analysis.findings.map(item => <div key={item.code} className="rounded-md border border-border bg-background/60 p-4"><div className="font-semibold">{item.title}</div><p className="mt-2 text-sm text-muted-foreground">{item.detail}</p></div>)}</div> : <p className="text-sm text-muted-foreground">No JWT metadata risks were recorded.</p>}
      </SectionCard>
      <div className="grid gap-6 xl:grid-cols-2">
        <SectionCard title="Decoded Header"><pre className="overflow-auto rounded-md bg-background/70 p-4 text-xs text-muted-foreground">{JSON.stringify(analysis.header, null, 2)}</pre></SectionCard>
        <SectionCard title="Decoded Payload"><pre className="overflow-auto rounded-md bg-background/70 p-4 text-xs text-muted-foreground">{JSON.stringify(analysis.payload, null, 2)}</pre></SectionCard>
      </div>
    </PageShell>
  );
}

