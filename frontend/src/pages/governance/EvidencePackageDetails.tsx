import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import type { GovernanceEvidencePackage } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import { PageHeader, PageShell, SectionCard } from "../../components/ui";
import { EvidenceItemTable } from "./components/EvidenceItemTable";
export function EvidencePackageDetails() {
  const { packageId } = useParams(),
    [data, setData] = useState<GovernanceEvidencePackage | null>(null);
  const reload=()=>vulnscopeApi.getEvidencePackage(Number(packageId)).then(setData);
  const add=async()=>{const source_module=window.prompt('Allowlisted source module','governance');const source_record_type=window.prompt('Source record type','risk');const id=Number(window.prompt('Source record ID'));if(!source_module||!source_record_type||!id)return;await vulnscopeApi.addEvidencePackageItem(Number(packageId),{source_module,source_record_type,source_record_id:id});await reload()};
  const report=async()=>{const item=await vulnscopeApi.createEvidencePackageReport(Number(packageId));window.location.assign(`/governance/reports/${item.id}`)};
  useEffect(() => {
    void vulnscopeApi.getEvidencePackage(Number(packageId)).then(setData);
  }, [packageId]);
  if (!data) return <PageShell>Loading evidence package…</PageShell>;
  return (
    <PageShell>
      <PageHeader
        title={`${data.package_key} · ${data.title}`}
        subtitle="Safe evidence inventory; original source files and external indicators are not exposed."
        actions={<div className="flex gap-2"><button onClick={()=>void add()} className="rounded bg-muted px-3 py-2">Add Safe Evidence</button><button onClick={()=>void report()} className="rounded bg-primary px-3 py-2">Generate Report</button></div>}
      />
      <SectionCard title="Evidence inventory">
        <EvidenceItemTable items={data.items} />
      </SectionCard>
    </PageShell>
  );
}
