import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { GovernanceRisk, GovernancePage } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
import { RiskScoreBadge } from "./components/RiskScoreBadge";
import { RiskSeverityBadge } from "./components/RiskSeverityBadge";
import { RiskStatusBadge } from "./components/RiskStatusBadge";
import { AppetiteStatusBadge } from "./components/AppetiteStatusBadge";
const empty = {
  q: "",
  category: "",
  origin: "",
  status: "",
  strategy: "",
  severity: "",
  confidence: "",
  appetite_status: "",
  owner: "",
  source_module: "",
  min_inherent_score: "",
  min_residual_score: "",
  due_from: "",
  due_to: "",
  next_review_from: "",
  next_review_to: "",
  framework: "",
};
export function RiskRegister() {
  const [data, setData] = useState<GovernancePage<GovernanceRisk> | null>(null),
    [filters, setFilters] = useState(empty),
    [page, setPage] = useState(1),
    [error, setError] = useState("");
  const createRisk = async () => {
    const title = window.prompt("Risk title");
    if (!title) return;
    const description = window.prompt("Risk description");
    if (!description) return;
    const created = await vulnscopeApi.createGovernanceRisk({ title, description, category: "other", likelihood: 3, impact: 3 });
    window.location.assign(`/governance/risks/${created.id}`);
  };
  useEffect(() => {
    const params = {
      ...Object.fromEntries(
        Object.entries(filters).filter(([, v]) => v !== ""),
      ),
      page,
      page_size: 25,
    };
    void vulnscopeApi
      .listGovernanceRisks(params)
      .then(setData)
      .catch(() => setError("Unable to load risk register."));
  }, [filters, page]);
  return (
    <PageShell>
      <PageHeader
        title="Governance Risk Register"
        subtitle="Local risk-management records with explainable inherent and residual scoring."
        actions={<button onClick={() => void createRisk()} className="rounded bg-primary px-3 py-2">Create Risk</button>}
      />
      <div className="grid gap-2 md:grid-cols-4">
        {Object.keys(empty).map((k) => (
          <input
            key={k}
            value={filters[k as keyof typeof filters]}
            onChange={(e) => {
              setFilters({ ...filters, [k]: e.target.value });
              setPage(1);
            }}
            placeholder={k.replaceAll("_", " ")}
            className="h-10 rounded border bg-background px-3"
          />
        ))}
        <button
          onClick={() => {
            setFilters(empty);
            setPage(1);
          }}
          className="rounded bg-muted"
        >
          Clear filters
        </button>
      </div>
      {error ? (
        <p className="text-destructive">{error}</p>
      ) : (
        <SectionCard title={`Risks (${data?.total || 0})`}>
          {data?.items.length ? (
            data.items.map((x) => (
              <Link
                key={x.id}
                to={`/governance/risks/${x.id}`}
                className="flex flex-wrap items-center justify-between gap-2 rounded border p-3"
              >
                <span>
                  <b>{x.risk_key}</b> · {x.title}
                  <span className="ml-2">
                    <RiskSeverityBadge value={x.severity} />
                  </span>
                </span>
                <span className="flex gap-2">
                  <RiskStatusBadge value={x.status} />
                  <RiskScoreBadge score={x.residual_score} />
                  <AppetiteStatusBadge value={x.appetite_status} />
                </span>
              </Link>
            ))
          ) : data ? (
            <EmptyState
              title="No matching governance risks"
              description="Clear filters or synchronize local source evidence."
            />
          ) : (
            <p>Loading risk register…</p>
          )}
          <div className="mt-4 flex justify-end gap-2">
            <button
              disabled={page === 1}
              onClick={() => setPage((x) => x - 1)}
              className="rounded bg-muted px-3 py-2"
            >
              Previous
            </button>
            <button
              disabled={!data || page * 25 >= data.total}
              onClick={() => setPage((x) => x + 1)}
              className="rounded bg-muted px-3 py-2"
            >
              Next
            </button>
          </div>
        </SectionCard>
      )}
    </PageShell>
  );
}
