import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { UnifiedEntity } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
import { EntityTypeBadge } from "./components/EntityTypeBadge";
import { EntityRiskBadge } from "./components/EntityRiskBadge";
const empty = {
  q: "",
  entity_type: "",
  severity: "",
  confidence: "",
  source_module: "",
  min_risk: "",
  watchlist_match: "",
  first_seen_from: "",
  first_seen_to: "",
  last_seen_from: "",
  last_seen_to: "",
};
export function UnifiedEntityList() {
  const [d, setD] = useState<{ items: UnifiedEntity[]; total: number } | null>(
      null,
    ),
    [f, setF] = useState(empty);
  useEffect(() => {
    const t = setTimeout(
      () =>
        void vulnscopeApi
          .listUnifiedEntities(
            Object.fromEntries(Object.entries(f).filter(([, v]) => v !== "")),
          )
          .then(setD),
      200,
    );
    return () => clearTimeout(t);
  }, [f]);
  return (
    <PageShell>
      <PageHeader
        title="Unified entities"
        subtitle="Redacted identities and safe hashes from local source records."
      />
      <div className="grid gap-2 md:grid-cols-4">
        <input
          value={f.q}
          onChange={(e) => setF({ ...f, q: e.target.value })}
          placeholder="Safe value or hash"
          className="h-10 rounded border border-input bg-background px-3"
        />
        <input
          value={f.entity_type}
          onChange={(e) => setF({ ...f, entity_type: e.target.value })}
          placeholder="Entity type"
          className="rounded border border-input bg-background px-3"
        />
        <input
          value={f.source_module}
          onChange={(e) => setF({ ...f, source_module: e.target.value })}
          placeholder="Source module"
          className="rounded border border-input bg-background px-3"
        />
        <input
          value={f.min_risk}
          onChange={(e) => setF({ ...f, min_risk: e.target.value })}
          placeholder="Minimum risk"
          className="rounded border border-input bg-background px-3"
        />
        <select
          value={f.severity}
          onChange={(e) => setF({ ...f, severity: e.target.value })}
          className="rounded border border-input bg-background px-3"
        >
          <option value="">All severities</option>
          {["info", "low", "medium", "high", "critical"].map((x) => (
            <option key={x}>{x}</option>
          ))}
        </select>
        <select
          value={f.confidence}
          onChange={(e) => setF({ ...f, confidence: e.target.value })}
          className="rounded border border-input bg-background px-3"
        >
          <option value="">All confidence</option>
          {["low", "medium", "high"].map((x) => (
            <option key={x}>{x}</option>
          ))}
        </select>
        <select
          value={f.watchlist_match}
          onChange={(e) => setF({ ...f, watchlist_match: e.target.value })}
          className="rounded border border-input bg-background px-3"
        >
          <option value="">Any watchlist state</option>
          <option value="true">Matched</option>
          <option value="false">Not matched</option>
        </select>
        <button onClick={() => setF(empty)} className="rounded bg-muted px-3">
          Clear filters
        </button>
      </div>
      <SectionCard title={`Entities (${d?.total || 0})`}>
        {d?.items.length ? (
          d.items.map((x) => (
            <Link
              key={x.id}
              to={`/correlation/entities/${x.id}`}
              className="flex justify-between rounded border border-border p-3"
            >
              <span>
                <EntityTypeBadge value={x.entity_type} />{" "}
                {x.display_value_redacted}
              </span>
              <span>
                <EntityRiskBadge score={x.risk_score} /> ·{" "}
                {x.source_module_count} modules
              </span>
            </Link>
          ))
        ) : (
          <EmptyState
            title="No matching entities"
            description="Clear filters or run local synchronization."
          />
        )}
      </SectionCard>
    </PageShell>
  );
}
