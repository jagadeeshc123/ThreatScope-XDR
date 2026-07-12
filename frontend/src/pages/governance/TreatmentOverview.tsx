import { useEffect, useState } from "react";
import type { RiskTreatmentPlan } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
import { TreatmentPlanPanel } from "./components/TreatmentPlanPanel";
export function TreatmentOverview() {
  const [items, setItems] = useState<RiskTreatmentPlan[] | null>(null);
  const load=()=>vulnscopeApi.listGovernanceTreatments().then(setItems);
  useEffect(() => {
    void vulnscopeApi.listGovernanceTreatments().then(setItems);
  }, []);
  const change=async(item:RiskTreatmentPlan,status:string)=>{const payload:Record<string,unknown>={status};if(status==='completed'){const summary=window.prompt('Required completion summary');if(!summary)return;payload.completion_summary=summary}await vulnscopeApi.updateGovernanceTreatment(item.risk_id,item.id,payload);await load()};
  return (
    <PageShell>
      <PageHeader
        title="Risk Treatments"
        subtitle="Workflow plans only; no technical remediation is executed."
      />
      <SectionCard>
        {items?.length ? (
          <><TreatmentPlanPanel items={items}/>{items.map(x=><div key={x.id} className="mt-2 flex gap-2">{['in_progress','completed','cancelled'].map(s=><button key={s} onClick={()=>void change(x,s)} className="rounded bg-muted px-2 py-1 text-xs">{x.title}: {s.replaceAll('_',' ')}</button>)}</div>)}</>
        ) : items ? (
          <EmptyState
            title="No treatment plans"
            description="Create a plan from a governance risk."
          />
        ) : (
          <p>Loading treatments…</p>
        )}
      </SectionCard>
    </PageShell>
  );
}
