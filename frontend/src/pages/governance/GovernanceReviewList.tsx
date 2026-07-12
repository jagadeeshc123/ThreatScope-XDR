import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { GovernanceReview } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
export function GovernanceReviewList() {
  const [items, setItems] = useState<GovernanceReview[] | null>(null);
  const create=async()=>{const title=window.prompt('Review title');if(!title)return;const end=new Date(),start=new Date(end.getTime()-30*86400000);const item=await vulnscopeApi.createGovernanceReview({title,review_type:'periodic',period_start:start.toISOString(),period_end:end.toISOString(),scope_summary:'Local governance evidence review.'});window.location.assign(`/governance/reviews/${item.id}`)};
  useEffect(() => {
    void vulnscopeApi.listGovernanceReviews().then(setItems);
  }, []);
  return (
    <PageShell>
      <PageHeader
        title="Governance Reviews"
        subtitle="Explicit review cycles with immutable completion snapshots."
        actions={<button onClick={()=>void create()} className="rounded bg-primary px-3 py-2">Create Governance Review</button>}
      />
      <SectionCard>
        {items?.length ? (
          items.map((x) => (
            <Link
              key={x.id}
              to={`/governance/reviews/${x.id}`}
              className="flex justify-between rounded border p-3"
            >
              <span>
                {x.review_key} · {x.title}
              </span>
              <span>
                {x.review_type} · {x.status}
              </span>
            </Link>
          ))
        ) : items ? (
          <EmptyState
            title="No governance reviews"
            description="Create a review from the governance workflow."
          />
        ) : (
          <p>Loading reviews…</p>
        )}
      </SectionCard>
    </PageShell>
  );
}
