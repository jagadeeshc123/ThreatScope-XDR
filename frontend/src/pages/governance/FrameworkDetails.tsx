import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import type { GovernanceFramework } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import { PageHeader, PageShell, SectionCard } from "../../components/ui";
import { FrameworkBadge } from "./components/FrameworkBadge";
import { ControlCoverageBadge } from "./components/ControlCoverageBadge";
export function FrameworkDetails() {
  const { frameworkId } = useParams(),
    [data, setData] = useState<GovernanceFramework | null>(null);
  const report = async () => { const created=await vulnscopeApi.createFrameworkCoverageReport(Number(frameworkId));window.location.assign(`/governance/reports/${created.id}`); };
  useEffect(() => {
    void vulnscopeApi.getGovernanceFramework(Number(frameworkId)).then(setData);
  }, [frameworkId]);
  if (!data) return <PageShell>Loading framework…</PageShell>;
  return (
    <PageShell>
      <PageHeader title={data.name} subtitle={data.disclaimer} actions={<button onClick={()=>void report()} className="rounded bg-primary px-3 py-2">Generate Coverage Report</button>} />
      <FrameworkBadge name={data.name} version={data.version} />
      <SectionCard title="Evidence coverage summary">
        <p>
          {data.coverage?.evidence_coverage_percentage || 0}% evidence coverage
          · {data.coverage?.supported_controls || 0} supported ·{" "}
          {data.coverage?.gap_controls || 0} gaps
        </p>
      </SectionCard>
      <SectionCard title="Control hierarchy">
        {data.coverage?.controls.map((x) => (
          <div key={x.control.id} className="rounded border p-3">
            <ControlCoverageBadge value={x.status} />{" "}
            <b className="ml-2">
              {x.control.control_key} · {x.control.title}
            </b>
            <p className="text-sm text-muted-foreground">{x.control.summary}</p>
          </div>
        ))}
      </SectionCard>
    </PageShell>
  );
}
