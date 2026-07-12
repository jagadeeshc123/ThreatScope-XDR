import { useCallback, useEffect, useState } from "react";
import type { GovernanceControlMapping } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
import { MappingStatusBadge } from "./components/MappingStatusBadge";
export function MappingReviewQueue() {
  const [items, setItems] = useState<GovernanceControlMapping[]>([]),
    [status, setStatus] = useState("candidate"),
    [error, setError] = useState("");
  const load = useCallback(() =>
    vulnscopeApi
      .listGovernanceMappings({ status })
      .then((x) => setItems(x.items))
      .catch(() => setError("Unable to load mappings.")), [status]);
  useEffect(() => {
    void load();
  }, [load]);
  const review = async (id: number, mapping_status: string) => {
    await vulnscopeApi.updateGovernanceMapping(id, {
      mapping_status,
      analyst_notes:
        mapping_status === "not_applicable"
          ? "Visible record marked not applicable by analyst."
          : "Reviewed by analyst.",
    });
    await load();
  };
  return (
    <PageShell>
      <PageHeader
        title="Mapping Review Queue"
        subtitle="Candidate control relationships never count as confirmed coverage until reviewed."
      />
      <select
        value={status}
        onChange={(e) => setStatus(e.target.value)}
        className="rounded border bg-background p-2"
      >
        {["candidate", "confirmed", "rejected", "not_applicable"].map((x) => (
          <option key={x}>{x}</option>
        ))}
      </select>
      {error ? (
        <p className="text-destructive">{error}</p>
      ) : (
        <SectionCard>
          {items.length ? (
            items.map((x) => (
              <div key={x.id} className="rounded border p-3">
                <MappingStatusBadge value={x.mapping_status} />{" "}
                <b className="ml-2">
                  {x.framework?.name} · {x.control?.control_key}
                </b>
                <p className="text-sm">
                  {x.risk?.risk_key} · {x.risk?.title}
                </p>
                <p className="text-sm text-muted-foreground">{x.rationale}</p>
                {x.mapping_status === "candidate" && (
                  <div className="mt-2 flex gap-2">
                    {["confirmed", "rejected", "not_applicable"].map((s) => (
                      <button
                        key={s}
                        onClick={() => void review(x.id, s)}
                        className="rounded bg-muted px-2 py-1 text-xs"
                      >
                        {s.replaceAll("_", " ")}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))
          ) : (
            <EmptyState
              title="No mappings in this queue"
              description="Generate deterministic candidates or select another status."
            />
          )}
        </SectionCard>
      )}
    </PageShell>
  );
}
