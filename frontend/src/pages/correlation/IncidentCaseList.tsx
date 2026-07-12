import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { IncidentCase } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
import { CasePriorityBadge } from "./components/CasePriorityBadge";
import { CaseStatusBadge } from "./components/CaseStatusBadge";
const empty = {
  q: "",
  status: "",
  severity: "",
  priority: "",
  confidence: "",
  case_type: "",
  assignee: "",
  source_module: "",
  entity_id: "",
  date_from: "",
  date_to: "",
};
export function IncidentCaseList() {
  const [d, setD] = useState<IncidentCase[]>([]),
    [f, setF] = useState(empty);
  useEffect(() => {
    void vulnscopeApi
      .listIncidentCases(
        Object.fromEntries(Object.entries(f).filter(([, v]) => v !== "")),
      )
      .then(setD);
  }, [f]);
  return (
    <PageShell>
      <PageHeader
        title="Incident cases"
        subtitle="Local analyst workflow; source records remain unchanged."
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
      <SectionCard title={`Cases (${d.length})`}>
        {d.length ? (
          d.map((x) => (
            <Link
              key={x.id}
              to={`/correlation/cases/${x.id}`}
              className="flex justify-between rounded border border-border p-3"
            >
              <span>
                {x.case_key} · {x.title}
              </span>
              <span>
                <CasePriorityBadge value={x.priority} />{" "}
                <CaseStatusBadge value={x.status} />
              </span>
            </Link>
          ))
        ) : (
          <EmptyState
            title="No matching incident cases"
            description="Clear filters or create a case."
          />
        )}
      </SectionCard>
    </PageShell>
  );
}
