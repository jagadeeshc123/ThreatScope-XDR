import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowLeft, RefreshCw, WandSparkles } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import type { ApiEndpoint, ApiIdentity, ApiRole, AuthorizationMatrixEntry } from '../../../types';
import { vulnscopeApi } from '../../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard } from '../../../components/ui';
import { IdentityManager } from './IdentityManager';
import { MatrixGrid } from './MatrixGrid';
import { RoleManager } from './RoleManager';

export function AuthorizationMatrix() {
  const assessmentId = Number(useParams().assessmentId);
  const [roles, setRoles] = useState<ApiRole[]>([]);
  const [identities, setIdentities] = useState<ApiIdentity[]>([]);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [entries, setEntries] = useState<AuthorizationMatrixEntry[]>([]);
  const [query, setQuery] = useState('');
  const [method, setMethod] = useState('');
  const [risk, setRisk] = useState('');
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const load = useCallback(async () => {
    const [roleRows, identityRows, endpointRows, matrixRows] = await Promise.all([
      vulnscopeApi.listApiRoles(assessmentId), vulnscopeApi.listApiIdentities(assessmentId), vulnscopeApi.listApiEndpoints(assessmentId), vulnscopeApi.listAuthorizationMatrix(assessmentId),
    ]);
    setRoles(roleRows); setIdentities(identityRows); setEndpoints(endpointRows); setEntries(matrixRows); setLoading(false);
  }, [assessmentId]);
  useEffect(() => { void load().catch(() => { setLoading(false); toast.error('Authorization matrix could not be loaded.'); }); }, [load]);

  const filtered = useMemo(() => endpoints.filter(endpoint => (!query || `${endpoint.path} ${endpoint.summary || ''}`.toLowerCase().includes(query.toLowerCase())) && (!method || endpoint.method === method) && (!risk || endpoint.preliminary_risk_level === risk)), [endpoints, method, query, risk]);
  const generate = async () => { setGenerating(true); try { const result = await vulnscopeApi.generateAuthorizationReview(assessmentId); toast.success(`${result.matrix_entries_created} cells and ${result.reviews_created} reviews generated.`); await load(); } catch { toast.error('Suggestions could not be generated.'); } finally { setGenerating(false); } };

  return <PageShell>
    <PageHeader title="Authorization Matrix" subtitle="Analyst-owned access expectations inferred from imported metadata. Suggestions do not confirm runtime authorization." actions={<><Link to={`/api-security/assessments/${assessmentId}`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold"><ArrowLeft className="h-4 w-4" />Assessment</Link><button disabled={generating || !roles.length} onClick={() => void generate()} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white disabled:opacity-50"><WandSparkles className="h-4 w-4" />{generating ? 'Generating' : 'Generate suggestions'}</button></>} />
    <div className="grid gap-6 xl:grid-cols-[1fr_1fr]"><SectionCard title="Roles" subtitle="Define expected privilege levels."><RoleManager assessmentId={assessmentId} roles={roles} onChange={load} /></SectionCard><SectionCard title="Identity Definitions" subtitle="Store labels and role mappings, never credentials."><IdentityManager assessmentId={assessmentId} identities={identities} roles={roles} onChange={load} /></SectionCard></div>
    <SectionCard title="Role and Endpoint Decisions" subtitle={`${entries.filter(item => item.review_status === 'reviewed').length} reviewed of ${Math.max(roles.length * endpoints.length, 0)} expected cells.`}>
      <div className="mb-4 grid gap-3 sm:grid-cols-3"><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search path or summary" className="rounded-md border border-border bg-background px-3 py-2 text-sm" /><select value={method} onChange={event => setMethod(event.target.value)} className="rounded-md border border-border bg-background px-3 py-2 text-sm"><option value="">All methods</option>{[...new Set(endpoints.map(item => item.method))].map(item => <option key={item}>{item}</option>)}</select><select value={risk} onChange={event => setRisk(event.target.value)} className="rounded-md border border-border bg-background px-3 py-2 text-sm"><option value="">All risks</option>{['high', 'medium', 'low', 'info'].map(item => <option key={item}>{item}</option>)}</select></div>
      {loading ? <p className="text-sm text-muted-foreground">Loading matrix...</p> : !roles.length ? <EmptyState title="Define roles first" description="Add roles, then generate metadata-based access suggestions." /> : !filtered.length ? <EmptyState title="No matching endpoints" description="Adjust the filters or import an API definition." /> : <MatrixGrid endpoints={filtered} roles={roles} entries={entries} onSave={async (endpointId, roleId, entry, draft) => { if (entry) await vulnscopeApi.updateAuthorizationMatrixEntry(entry.id, draft); else await vulnscopeApi.createAuthorizationMatrixEntry(assessmentId, { endpoint_id: endpointId, role_id: roleId, ...draft }); await load(); toast.success('Matrix cell saved.'); }} />}
      <button onClick={() => void load()} className="mt-4 inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm"><RefreshCw className="h-4 w-4" />Refresh matrix</button>
    </SectionCard>
  </PageShell>;
}
