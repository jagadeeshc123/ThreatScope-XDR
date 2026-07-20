import { useCallback, useEffect, useState } from 'react';
import { RefreshCw, ShieldCheck } from 'lucide-react';
import { apiClient } from '../../api/client';
import { useAuth } from '../../auth/useAuth';

type Check = { name: string; state: 'pass' | 'warning' | 'failure'; summary: string; remediation_code: string };
type Readiness = { ready: boolean; status: string; failure_count: number; warning_count: number; checks: Check[] };
type BuildInfo = { application_version: string; schema_identifier: string; source_revision: string; runtime_profile: string; frontend_build_identifier: string; backend_build_identifier: string };
type Posture = Record<string, string | boolean | number>;

const tone = (state: string) => state === 'pass' || state === 'ready' ? 'bg-emerald-500/15 text-emerald-300' : state === 'warning' ? 'bg-amber-500/15 text-amber-200' : 'bg-red-500/15 text-red-200';

export function ProductionReadinessPage() {
  const { can } = useAuth();
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [build, setBuild] = useState<BuildInfo | null>(null);
  const [posture, setPosture] = useState<Posture | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const [readyResponse, buildResponse] = await Promise.all([
        apiClient.get('/operations/production/readiness'),
        apiClient.get('/operations/production/build-info'),
      ]);
      setReadiness(readyResponse.data); setBuild(buildResponse.data);
      if (can('operations:diagnostics')) setPosture((await apiClient.get('/operations/production/security-posture')).data);
    } catch (value) {
      setError(value instanceof Error ? value.message : 'Production readiness could not be loaded.');
    } finally { setLoading(false); }
  }, [can]);
  useEffect(() => { void load(); }, [load]);
  const runPreflight = async () => { await apiClient.post('/operations/production/preflight'); await load(); };

  return <div className="mx-auto max-w-7xl space-y-6 p-4 sm:p-6">
    <header className="flex flex-wrap items-start justify-between gap-4"><div><h1 className="text-2xl font-semibold">Production readiness</h1><p className="mt-1 text-sm text-muted-foreground">Safe deployment posture and remediation guidance. Secret values and filesystem paths are never displayed.</p></div><div className="flex gap-2"><button className="rounded border border-border p-2" onClick={() => void load()} aria-label="Refresh production readiness"><RefreshCw className="h-4 w-4" /></button>{can('system:manage') && <button className="inline-flex items-center gap-2 rounded bg-primary px-3 py-2 text-sm text-primary-foreground" onClick={() => void runPreflight()}><ShieldCheck className="h-4 w-4" />Run preflight</button>}</div></header>
    {loading ? <div className="rounded border border-border p-8 text-muted-foreground">Loading production readiness…</div> : error ? <div role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-4 text-red-200">{error}</div> : !readiness || !build ? <div className="rounded border border-border p-8 text-muted-foreground">No production-readiness data is available.</div> : <>
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <article className="rounded border border-border bg-card p-4"><p className="text-xs uppercase text-muted-foreground">Status</p><span className={`mt-2 inline-flex rounded-full px-2 py-1 text-sm ${tone(readiness.status)}`}>{readiness.status}</span></article>
        <article className="rounded border border-border bg-card p-4"><p className="text-xs uppercase text-muted-foreground">Profile</p><p className="mt-2 font-semibold">{build.runtime_profile}</p></article>
        <article className="rounded border border-border bg-card p-4"><p className="text-xs uppercase text-muted-foreground">Application</p><p className="mt-2 font-semibold">{build.application_version}</p></article>
        <article className="rounded border border-border bg-card p-4"><p className="text-xs uppercase text-muted-foreground">Schema</p><p className="mt-2 font-semibold">{build.schema_identifier}</p></article>
      </section>
      <section className="overflow-x-auto rounded border border-border"><table className="w-full min-w-[720px] text-sm"><thead className="bg-muted/40 text-left"><tr><th className="p-3">Check</th><th>State</th><th>Summary</th><th>Remediation</th></tr></thead><tbody>{readiness.checks.map(check => <tr className="border-t border-border" key={check.name}><td className="p-3 font-medium">{check.name.replaceAll('_', ' ')}</td><td><span className={`rounded-full px-2 py-1 text-xs ${tone(check.state)}`}>{check.state}</span></td><td className="max-w-xl py-3 pr-3">{check.summary}</td><td className="font-mono text-xs">{check.remediation_code}</td></tr>)}</tbody></table></section>
      <section className="grid gap-4 lg:grid-cols-2"><article className="rounded border border-border bg-card p-4"><h2 className="font-semibold">Release identity</h2><dl className="mt-3 grid gap-2 text-sm"><div><dt className="text-muted-foreground">Source revision</dt><dd className="break-all font-mono">{build.source_revision}</dd></div><div><dt className="text-muted-foreground">Frontend build</dt><dd>{build.frontend_build_identifier}</dd></div><div><dt className="text-muted-foreground">Backend build</dt><dd>{build.backend_build_identifier}</dd></div></dl></article>{posture && <article className="rounded border border-border bg-card p-4"><h2 className="font-semibold">Security posture</h2><dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">{Object.entries(posture).map(([key, value]) => <div key={key}><dt className="text-muted-foreground">{key.replaceAll('_', ' ')}</dt><dd>{String(value)}</dd></div>)}</dl></article>}</section>
    </>}
  </div>;
}
