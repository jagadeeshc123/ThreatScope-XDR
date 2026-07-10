import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { Eraser, KeyRound, Search } from 'lucide-react';
import { toast } from 'sonner';
import type { ApiAssessment, JwtAnalysis } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard, StatCard } from '../../components/ui';
import { ApiRiskBadge } from './components/ApiRiskBadge';

export function JwtAnalyzer() {
  const [token, setToken] = useState('');
  const [assessmentId, setAssessmentId] = useState('');
  const [expectedIssuer, setExpectedIssuer] = useState('');
  const [expectedAudience, setExpectedAudience] = useState('');
  const [assessments, setAssessments] = useState<ApiAssessment[]>([]);
  const [history, setHistory] = useState<JwtAnalysis[]>([]);
  const [result, setResult] = useState<JwtAnalysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  useEffect(() => {
    void Promise.all([
      vulnscopeApi.listApiAssessments().catch(() => []),
      vulnscopeApi.listJwtAnalyses().catch(() => []),
    ]).then(([apiAssessments, analyses]) => {
      setAssessments(apiAssessments);
      setHistory(analyses);
    });
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAnalyzing(true);
    try {
      const analysis = await vulnscopeApi.analyzeJwt({
        token,
        assessment_id: assessmentId ? Number(assessmentId) : null,
        expected_issuer: expectedIssuer.trim() || null,
        expected_audience: expectedAudience.trim() || null,
      });
      setToken('');
      setResult(analysis);
      setHistory(current => [analysis, ...current.filter(item => item.id !== analysis.id)]);
      toast.success('JWT analyzed without storing the raw token');
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'JWT could not be analyzed');
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <PageShell>
      <PageHeader title="JWT Analyzer" subtitle="Decode JWT structure locally in the backend and store only redacted metadata plus a SHA-256 fingerprint." />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <SectionCard title="Analyze Token" icon={<KeyRound className="h-5 w-5" />}>
          <form onSubmit={submit} className="space-y-5">
            <div className="rounded-md border border-amber-400/30 bg-amber-500/10 p-3 text-sm text-amber-100">
              Decoded structure only - cryptographic signature not verified.
            </div>
            <label className="block text-sm font-medium text-foreground">
              Token
              <textarea value={token} onChange={event => setToken(event.target.value)} required rows={7} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs outline-none focus:border-indigo-400" />
            </label>
            <div className="grid gap-4 md:grid-cols-3">
              <label className="text-sm font-medium text-foreground">Assessment<select value={assessmentId} onChange={event => setAssessmentId(event.target.value)} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"><option value="">Unlinked</option>{assessments.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
              <label className="text-sm font-medium text-foreground">Expected issuer<input value={expectedIssuer} onChange={event => setExpectedIssuer(event.target.value)} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm" /></label>
              <label className="text-sm font-medium text-foreground">Expected audience<input value={expectedAudience} onChange={event => setExpectedAudience(event.target.value)} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm" /></label>
            </div>
            <div className="flex flex-wrap gap-3">
              <button disabled={analyzing} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white hover:bg-indigo-400 disabled:opacity-60"><Search className="h-4 w-4" /> {analyzing ? 'Analyzing...' : 'Analyze'}</button>
              <button type="button" onClick={() => { setToken(''); setResult(null); }} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted"><Eraser className="h-4 w-4" /> Clear</button>
            </div>
          </form>
        </SectionCard>
        <SectionCard title="Analysis History">
          {history.length ? (
            <div className="space-y-3">
              {history.slice(0, 10).map(item => <Link key={item.id} to={`/api-security/jwt/${item.id}`} className="block rounded-md border border-border bg-background/60 p-3 hover:border-indigo-300"><div className="font-mono text-xs">{item.token_fingerprint.slice(0, 20)}</div><div className="mt-2 text-sm text-muted-foreground">{item.algorithm || 'No alg'} | {item.expiration_status} | risk {item.risk_score}/10</div></Link>)}
            </div>
          ) : <EmptyState title="No JWT analyses" description="Decoded JWT metadata will appear here after analysis." />}
        </SectionCard>
      </div>
      {result && (
        <div className="grid gap-6 xl:grid-cols-3">
          <StatCard label="Risk Score" value={`${result.risk_score}/10`} tone={result.risk_score >= 7 ? 'danger' : result.risk_score >= 4 ? 'warn' : 'info'} />
          <StatCard label="Algorithm" value={result.algorithm || 'Missing'} />
          <StatCard label="Expiration" value={result.expiration_status} />
          <SectionCard className="xl:col-span-3" title="Detected Risks">
            {result.findings.length ? <div className="grid gap-3">{result.findings.map(item => <div key={`${item.code}-${item.title}`} className="rounded-md border border-border bg-background/60 p-4"><div className="flex items-center justify-between gap-3"><h3 className="font-semibold">{item.title}</h3><ApiRiskBadge risk={item.severity === 'critical' ? 'high' : item.severity as any} /></div><p className="mt-2 text-sm text-muted-foreground">{item.detail}</p></div>)}</div> : <p className="text-sm text-muted-foreground">No obvious JWT metadata risks found.</p>}
          </SectionCard>
          <JsonBlock title="Decoded Header" value={result.header} />
          <JsonBlock title="Decoded Payload" value={result.payload} />
        </div>
      )}
    </PageShell>
  );
}

function JsonBlock({ title, value }: { title: string; value: Record<string, unknown> }) {
  return <SectionCard title={title}><pre className="max-h-96 overflow-auto rounded-md bg-background/70 p-4 text-xs text-muted-foreground">{JSON.stringify(value, null, 2)}</pre></SectionCard>;
}
