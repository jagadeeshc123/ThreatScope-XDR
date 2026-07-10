import type { ApiBusinessFlowRisk } from '../../../types';
import { FlowRiskCard } from './FlowRiskCard';

export function BusinessFlowRisks({ risks, onStatus }: { risks: ApiBusinessFlowRisk[]; onStatus?: (risk: ApiBusinessFlowRisk, status: ApiBusinessFlowRisk['status']) => void }) {
  return <div className="space-y-4">{risks.map(risk => <FlowRiskCard key={risk.id} risk={risk} onStatus={onStatus ? status => onStatus(risk, status) : undefined} />)}</div>;
}
