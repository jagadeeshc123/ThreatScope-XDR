import type { ApiBusinessFlowRisk } from '../../../types';
import { SeverityBadge } from '../../../components/ui';
import { ReviewStatusBadge } from '../authorization/ReviewStatusBadge';

export function FlowRiskCard({ risk, onStatus }: { risk: ApiBusinessFlowRisk; onStatus?: (status: ApiBusinessFlowRisk['status']) => void }) {
  return <article className="rounded-md border border-border bg-background/50 p-4"><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={risk.severity} /><ReviewStatusBadge status={risk.status} /><span className="text-xs text-muted-foreground">{risk.owasp_category || 'Unmapped'} | {risk.confidence} confidence</span></div><h3 className="mt-3 font-semibold">{risk.title}</h3><p className="mt-2 text-sm leading-6 text-muted-foreground">{risk.description}</p><p className="mt-2 text-sm"><strong>Evidence:</strong> <span className="text-muted-foreground">{risk.evidence_summary}</span></p><p className="mt-2 text-sm"><strong>Remediation:</strong> <span className="text-muted-foreground">{risk.remediation}</span></p>{onStatus && <select value={risk.status} onChange={event => onStatus(event.target.value as ApiBusinessFlowRisk['status'])} className="mt-4 rounded-md border border-border bg-background px-3 py-2 text-sm">{['open', 'accepted', 'resolved'].map(item => <option key={item}>{item}</option>)}</select>}</article>;
}
