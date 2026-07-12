import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import type { GovernanceReview } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import { PageHeader, PageShell, SectionCard } from "../../components/ui";
import { ReviewSnapshotPanel } from "./components/ReviewSnapshotPanel";
export function GovernanceReviewDetails() {
  const { reviewId } = useParams(),
    [data, setData] = useState<GovernanceReview | null>(null);
  const reload=()=>vulnscopeApi.getGovernanceReview(Number(reviewId)).then(setData);
  const advance=async(status:string)=>{if(status==='completed'){const conclusions=window.prompt('Required review conclusions');if(!conclusions)return;await vulnscopeApi.completeGovernanceReview(Number(reviewId),conclusions)}else await vulnscopeApi.updateGovernanceReview(Number(reviewId),{status});await reload()};
  useEffect(() => {
    void vulnscopeApi.getGovernanceReview(Number(reviewId)).then(setData);
  }, [reviewId]);
  if (!data) return <PageShell>Loading governance review…</PageShell>;
  return (
    <PageShell>
      <PageHeader
        title={`${data.review_key} · ${data.title}`}
        subtitle={`${data.period_start.slice(0, 10)} to ${data.period_end.slice(0, 10)} · ${data.status}`}
        actions={data.status==='completed'?undefined:<div className="flex gap-2">{['in_progress','awaiting_approval','completed','cancelled'].map(s=><button key={s} onClick={()=>void advance(s)} className="rounded bg-muted px-2 py-1 text-xs">{s.replaceAll('_',' ')}</button>)}</div>}
      />
      <SectionCard title="Scope">{data.scope_summary}</SectionCard>
      <SectionCard title="Conclusions">
        {data.conclusions ||
          "Conclusions are required for explicit completion."}
      </SectionCard>
      <SectionCard title="Immutable completion snapshot">
        <ReviewSnapshotPanel snapshot={data.snapshot} />
      </SectionCard>
    </PageShell>
  );
}
