import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { CorrelationMatch } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
import { MatchSeverityBadge } from "./components/MatchSeverityBadge";
const empty = {
  rule_code: "",
  status: "",
  severity: "",
  confidence: "",
  source_module: "",
  min_score: "",
  date_from: "",
  date_to: "",
};
export function CorrelationMatchList() {
  const [d, setD] = useState<CorrelationMatch[]>([]),
    [f, setF] = useState(empty);
  useEffect(() => {
    void vulnscopeApi
      .listCorrelationMatches(
        Object.fromEntries(Object.entries(f).filter(([, v]) => v !== "")),
      )
      .then(setD);
  }, [f]);
  return (
    <PageShell>
      <PageHeader
        title="Correlation matches"
        subtitle="Explainable possible relationships requiring analyst validation."
      />
      <div className="grid gap-2 md:grid-cols-4">
        {Object.keys(empty).map((k) => (
          <input
            key={k}
            value={f[k as keyof typeof f]}
            onChange={(e) => setF({ ...f, [k]: e.target.value })}
            placeholder={k.replaceAll("_", " ")}
            className="h-10 rounded border border-input bg-background px-3"
          />
        ))}
        <button onClick={() => setF(empty)} className="rounded bg-muted">
          Clear filters
        </button>
      </div>
      <SectionCard title={`Matches (${d.length})`}>
        {d.length ? (
          d.map((x) => (
            <Link
              key={x.id}
              to={`/correlation/matches/${x.id}`}
              className="flex justify-between rounded border border-border p-3"
            >
              <span>
                {x.rule_code} · {x.title}
              </span>
              <span>
                <MatchSeverityBadge value={x.severity} /> {x.match_score}/100 ·{" "}
                {x.status}
              </span>
            </Link>
          ))
        ) : (
          <EmptyState
            title="No matching correlations"
            description="Clear filters or run correlation."
          />
        )}
      </SectionCard>
    </PageShell>
  );
}
