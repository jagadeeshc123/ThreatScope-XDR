import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import type { GovernanceRisk } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import { PageHeader, PageShell, SectionCard } from "../../components/ui";
import { RiskScoreBadge } from "./components/RiskScoreBadge";
import { RiskSeverityBadge } from "./components/RiskSeverityBadge";
import { RiskStatusBadge } from "./components/RiskStatusBadge";
import { AppetiteStatusBadge } from "./components/AppetiteStatusBadge";
import { RiskSourcePanel } from "./components/RiskSourcePanel";
import { ControlMappingPanel } from "./components/ControlMappingPanel";
import { TreatmentPlanPanel } from "./components/TreatmentPlanPanel";
import { RiskExceptionPanel } from "./components/RiskExceptionPanel";
import { GovernanceDisclaimer } from "./components/GovernanceDisclaimer";
export function RiskDetails() {
  const { riskId } = useParams(),
    [risk, setRisk] = useState<GovernanceRisk | null>(null),
    [error, setError] = useState("");
  const reload = () => vulnscopeApi.getGovernanceRisk(Number(riskId)).then(setRisk);
  const update = async (kind: "owner" | "status" | "strategy" | "score") => {
    const payload: Record<string, unknown> = {};
    if (kind === "owner") payload.owner_name = window.prompt("Risk owner", risk?.owner_name || "") || "";
    if (kind === "strategy") payload.treatment_strategy = window.prompt("Strategy: mitigate, accept, avoid, transfer, or monitor", risk?.treatment_strategy) || risk?.treatment_strategy;
    if (kind === "status") {
      const status = window.prompt("Risk status", risk?.status); if (!status) return; payload.status = status;
      if (status === "accepted") payload.acceptance_justification = window.prompt("Acceptance justification (or cancel to rely on an active exception)") || undefined;
      if (status === "closed") payload.resolution_summary = window.prompt("Required resolution summary") || "";
    }
    if (kind === "score") {
      payload.likelihood = Number(window.prompt("Likelihood 1-5", String(risk?.likelihood || 3)));
      payload.impact = Number(window.prompt("Impact 1-5", String(risk?.impact || 3)));
      payload.residual_likelihood = Number(window.prompt("Residual likelihood 1-5", String(risk?.residual_likelihood || 3)));
      payload.residual_impact = Number(window.prompt("Residual impact 1-5", String(risk?.residual_impact || 3)));
      payload.adjustment_rationale = window.prompt("Required scoring rationale") || "";
    }
    await vulnscopeApi.updateGovernanceRisk(Number(riskId), payload); await reload();
  };
  const addTreatment = async () => { const title=window.prompt("Treatment title"); if(!title)return; await vulnscopeApi.createGovernanceTreatment(Number(riskId),{title,description:"Analyst workflow plan; no remediation is executed.",strategy:"mitigate"});await reload(); };
  const addException = async () => { const justification=window.prompt("Exception justification"); if(!justification)return; await vulnscopeApi.requestGovernanceException(Number(riskId),{justification});await reload(); };
  useEffect(() => {
    void vulnscopeApi
      .getGovernanceRisk(Number(riskId))
      .then(setRisk)
      .catch(() => setError("Risk not found."));
  }, [riskId]);
  if (error)
    return (
      <PageShell>
        <p className="text-destructive">{error}</p>
      </PageShell>
    );
  if (!risk) return <PageShell>Loading governance risk…</PageShell>;
  return (
    <PageShell>
      <PageHeader
        title={`${risk.risk_key} · ${risk.title}`}
        subtitle={risk.description}
        actions={<div className="flex flex-wrap gap-2">{([['owner','Owner'],['status','Status'],['strategy','Strategy'],['score','Adjust Scores']] as const).map(([k,l])=><button key={k} onClick={()=>void update(k)} className="rounded bg-muted px-3 py-2">{l}</button>)}<button onClick={()=>void addTreatment()} className="rounded bg-muted px-3 py-2">Create Treatment</button><button onClick={()=>void addException()} className="rounded bg-muted px-3 py-2">Request Exception</button></div>}
      />
      <GovernanceDisclaimer />
      <div className="flex flex-wrap gap-2">
        <RiskSeverityBadge value={risk.severity} />
        <RiskStatusBadge value={risk.status} />
        <RiskScoreBadge score={risk.inherent_score} label="Inherent" />
        <RiskScoreBadge score={risk.residual_score} />
        <AppetiteStatusBadge value={risk.appetite_status} />
      </div>
      <SectionCard title="Scoring and ownership">
        <div className="grid gap-3 md:grid-cols-4">
          <p>Likelihood: {risk.likelihood}/5</p>
          <p>Impact: {risk.impact}/5</p>
          <p>Owner: {risk.owner_name || "Unassigned"}</p>
          <p>Strategy: {risk.treatment_strategy}</p>
        </div>
      </SectionCard>
      <SectionCard title="Source evidence">
        <RiskSourcePanel items={risk.sources} />
      </SectionCard>
      <SectionCard title="Control mappings">
        <ControlMappingPanel items={risk.mappings} />
      </SectionCard>
      <SectionCard title="Treatment plans">
        <TreatmentPlanPanel items={risk.treatments} />
      </SectionCard>
      <SectionCard title="Risk exceptions">
        <RiskExceptionPanel items={risk.exceptions} />
      </SectionCard>
    </PageShell>
  );
}
