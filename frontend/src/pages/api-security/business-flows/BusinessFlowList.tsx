import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowLeft, ArrowRight, Plus, Trash2 } from 'lucide-react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import type { ApiBusinessFlow } from '../../../types';
import { vulnscopeApi } from '../../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard, RiskScoreBadge } from '../../../components/ui';

export function BusinessFlowList() {
  const assessmentId = Number(useParams().assessmentId);
  const navigate = useNavigate();
  const [flows, setFlows] = useState<ApiBusinessFlow[]>([]);
  const [name, setName] = useState(''); const [description, setDescription] = useState(''); const [roles, setRoles] = useState('');
  const load = useCallback(async () => setFlows(await vulnscopeApi.listBusinessFlows(assessmentId)), [assessmentId]);
  useEffect(() => { void load().catch(() => toast.error('Business flows could not be loaded.')); }, [load]);
  const submit = async (event: FormEvent) => { event.preventDefault(); const flow = await vulnscopeApi.createBusinessFlow(assessmentId, { name, description, actor_roles: roles.split(',').map(item => item.trim()).filter(Boolean) }); navigate(`/api-security/business-flows/${flow.id}/edit`); };
  return <PageShell><PageHeader title="Business Flows" subtitle="Model actor roles, ordered API steps, prerequisites, and state transitions for passive design review." actions={<Link to={`/api-security/assessments/${assessmentId}`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold"><ArrowLeft className="h-4 w-4" />Assessment</Link>} />
    <div className="grid gap-6 xl:grid-cols-[360px_1fr]"><SectionCard title="Create Flow"><form onSubmit={event => void submit(event)} className="space-y-3"><label className="block text-xs font-semibold text-muted-foreground">Name<input required value={name} onChange={event => setName(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm" /></label><label className="block text-xs font-semibold text-muted-foreground">Description<textarea required value={description} onChange={event => setDescription(event.target.value)} rows={4} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm" /></label><label className="block text-xs font-semibold text-muted-foreground">Actor roles<input value={roles} onChange={event => setRoles(event.target.value)} placeholder="User, Admin" className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm" /></label><button className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white"><Plus className="h-4 w-4" />Create flow</button></form></SectionCard>
      <SectionCard title="Flow Inventory" subtitle={`${flows.length} configured flow${flows.length === 1 ? '' : 's'}`}>{!flows.length ? <EmptyState title="No business flows" description="Create a flow from real business requirements and imported endpoint inventory." /> : <div className="space-y-3">{flows.map(flow => <article key={flow.id} className="flex flex-col gap-4 rounded-md border border-border bg-background/50 p-4 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold">{flow.name}</h3><span className="text-xs capitalize text-muted-foreground">{flow.status}</span></div><p className="mt-1 text-sm text-muted-foreground">{flow.description}</p><p className="mt-2 text-xs text-indigo-200">{flow.steps.length} steps | {flow.risks.length} indicators | {flow.actor_roles.join(', ') || 'Actors not defined'}</p></div><div className="flex items-center gap-3"><RiskScoreBadge score={flow.risk_score} max={100} /><Link to={`/api-security/business-flows/${flow.id}`} title="Open flow" className="rounded-md p-2 hover:bg-muted"><ArrowRight className="h-4 w-4" /></Link><button onClick={() => void vulnscopeApi.deleteBusinessFlow(flow.id).then(load)} title="Delete flow" className="rounded-md p-2 text-muted-foreground hover:bg-red-500/10 hover:text-red-200"><Trash2 className="h-4 w-4" /></button></div></article>)}</div>}</SectionCard></div>
  </PageShell>;
}
