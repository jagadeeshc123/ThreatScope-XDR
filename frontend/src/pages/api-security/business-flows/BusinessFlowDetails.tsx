import { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Pencil, Play } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import type { ApiBusinessFlow, ApiBusinessFlowRisk, ApiEndpoint } from '../../../types';
import { vulnscopeApi } from '../../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, RiskScoreBadge, SectionCard } from '../../../components/ui';
import { BusinessFlowRisks } from './BusinessFlowRisks';
import { FlowStepCard } from './FlowStepCard';

export function BusinessFlowDetails() {
  const flowId = Number(useParams().flowId); const [flow, setFlow] = useState<ApiBusinessFlow | null>(null); const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]); const [analyzing, setAnalyzing] = useState(false);
  const load = useCallback(async () => { const item = await vulnscopeApi.getBusinessFlow(flowId); setFlow(item); setEndpoints(await vulnscopeApi.listApiEndpoints(item.assessment_id)); }, [flowId]);
  useEffect(() => { void load().catch(() => toast.error('Business flow could not be loaded.')); }, [load]);
  if (!flow) return <PageShell><p className="text-sm text-muted-foreground">Loading business flow...</p></PageShell>;
  const analyze = async () => { setAnalyzing(true); try { const result = await vulnscopeApi.analyzeBusinessFlow(flow.id); toast.success(`${result.risks_total} passive indicators reviewed.`); await load(); } finally { setAnalyzing(false); } };
  const updateRisk = async (risk: ApiBusinessFlowRisk, status: ApiBusinessFlowRisk['status']) => { await vulnscopeApi.updateBusinessFlowRisk(risk.id, status); await load(); };
  return <PageShell><PageHeader title={flow.name} subtitle={flow.description} actions={<><Link to={`/api-security/assessments/${flow.assessment_id}/business-flows`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold"><ArrowLeft className="h-4 w-4" />Flows</Link><Link to={`/api-security/business-flows/${flow.id}/edit`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold"><Pencil className="h-4 w-4" />Edit steps</Link><button disabled={analyzing || !flow.steps.length} onClick={() => void analyze()} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white disabled:opacity-50"><Play className="h-4 w-4" />{analyzing ? 'Reviewing' : 'Run passive review'}</button></>} />
    <div className="grid gap-4 sm:grid-cols-3"><SectionCard title="Status"><p className="capitalize">{flow.status}</p></SectionCard><SectionCard title="Actors"><p>{flow.actor_roles.join(', ') || 'Not documented'}</p></SectionCard><SectionCard title="Risk Score"><RiskScoreBadge score={flow.risk_score} max={100} /></SectionCard></div>
    <SectionCard title="Ordered Steps">{flow.steps.length ? <div className="space-y-5">{flow.steps.map(step => <FlowStepCard key={step.id} step={step} endpoint={endpoints.find(item => item.id === step.endpoint_id)} />)}</div> : <EmptyState title="No steps configured" description="Open the editor to link imported endpoints and document workflow state." />}</SectionCard>
    <SectionCard title="Business Flow Risk Review" subtitle="Possible design weaknesses only; runtime behavior was not tested.">{flow.risks.length ? <BusinessFlowRisks risks={flow.risks} onStatus={(risk, status) => void updateRisk(risk, status)} /> : <EmptyState title="No risk indicators" description="Run the passive design review after configuring flow steps." />}</SectionCard>
  </PageShell>;
}
