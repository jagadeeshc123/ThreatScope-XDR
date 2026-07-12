import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import type { GovernanceOverview as Overview } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import { PageHeader, PageShell, SectionCard } from "../../components/ui";
import { GovernanceDisclaimer } from "./components/GovernanceDisclaimer";
import { ExecutiveSummaryCards } from "./components/ExecutiveSummaryCards";
import { RiskTrendChart } from "./components/RiskTrendChart";
import { ControlCoverageChart } from "./components/ControlCoverageChart";
import { RiskMatrix } from "./components/RiskMatrix";
export function GovernanceOverview() {
  const [data, setData] = useState<Overview | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [summary, setSummary] = useState("");
  const load = () =>
    vulnscopeApi
      .getGovernanceOverview()
      .then(setData)
      .catch(() => setError("Unable to load governance metrics."));
  useEffect(() => {
    void load();
  }, []);
  const run = async (kind: string) => {
    if (busy) return;
    setBusy(true);
    try {
      const result =
        kind === "sync"
          ? await vulnscopeApi.syncGovernanceRisks()
          : kind === "map"
            ? await vulnscopeApi.generateGovernanceMappings()
            : kind === "snapshot"
              ? await vulnscopeApi.captureGovernanceSnapshot()
              : kind === "exceptions"
                ? await vulnscopeApi.checkGovernanceExceptions()
                : kind === "overdue"
                  ? await vulnscopeApi.checkOverdueGovernance()
                : kind === "seed"
                  ? await vulnscopeApi.seedGovernanceFrameworks()
                  : await vulnscopeApi.createExecutiveGovernanceReport();
      setSummary(JSON.stringify(result, null, 2));
      toast.success("Local governance operation completed");
      await load();
    } catch {
      toast.error("Governance operation failed");
    } finally {
      setBusy(false);
    }
  };
  if (error)
    return (
      <PageShell>
        <p className="text-destructive">{error}</p>
      </PageShell>
    );
  if (!data) return <PageShell>Loading governance overview…</PageShell>;
  return (
    <PageShell>
      <PageHeader
        title="Governance & Reporting"
        subtitle="Executive risk management and evidence-supported framework mapping."
        actions={
          <div className="flex flex-wrap gap-2">
            <Link to="/governance/risks" className="rounded bg-muted px-3 py-2 text-sm">Create Risk</Link>
            <Link to="/governance/reviews" className="rounded bg-muted px-3 py-2 text-sm">Create Governance Review</Link>
            {[
              ["seed", "Seed Frameworks"],
              ["sync", "Synchronize Risks"],
              ["map", "Generate Candidate Mappings"],
              ["snapshot", "Capture Snapshot"],
              ["exceptions", "Check Expired Exceptions"],
              ["overdue", "Check Overdue Work"],
              ["report", "Executive Report"],
            ].map(([k, l]) => (
              <button
                key={k}
                disabled={busy}
                onClick={() => void run(k)}
                className="rounded bg-primary px-3 py-2 text-sm disabled:opacity-50"
              >
                {l}
              </button>
            ))}
          </div>
        }
      />
      <GovernanceDisclaimer />
      <ExecutiveSummaryCards data={data} />
      {summary && (
        <pre className="max-h-64 overflow-auto rounded bg-muted p-3 text-xs">
          {summary}
        </pre>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Risk trend">
          <RiskTrendChart items={data.risk_trend} />
        </SectionCard>
        <SectionCard title="Evidence coverage by framework">
          <ControlCoverageChart items={data.control_coverage_by_framework} />
        </SectionCard>
        <SectionCard title="Transparent 5 × 5 risk matrix">
          <RiskMatrix />
        </SectionCard>
        <SectionCard title="Recent risks">
          {data.recent_risks.length ? (
            data.recent_risks.map((x) => (
              <Link
                key={x.id}
                to={`/governance/risks/${x.id}`}
                className="block rounded border p-3"
              >
                {x.risk_key} · {x.title}
              </Link>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">
              No governance risks yet.
            </p>
          )}
        </SectionCard>
      </div>
    </PageShell>
  );
}
