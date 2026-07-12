import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import type { GovernanceEvidencePackage } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
export function EvidencePackageList() {
  const [items, setItems] = useState<GovernanceEvidencePackage[] | null>(null);
  const create=async()=>{const title=window.prompt('Evidence package title');if(!title)return;const item=await vulnscopeApi.createEvidencePackage({title,description:'Local bounded evidence package'});window.location.assign(`/governance/evidence/${item.id}`)};
  useEffect(() => {
    void vulnscopeApi.listEvidencePackages().then(setItems);
  }, []);
  return (
    <PageShell>
      <PageHeader
        title="Evidence Packages"
        subtitle="Bounded local snapshots with internal source references only."
        actions={<button onClick={()=>void create()} className="rounded bg-primary px-3 py-2">Create Package</button>}
      />
      <SectionCard>
        {items?.length ? (
          items.map((x) => (
            <Link
              key={x.id}
              to={`/governance/evidence/${x.id}`}
              className="flex justify-between rounded border p-3"
            >
              <span>
                {x.package_key} · {x.title}
              </span>
              <span>
                {x.status} · {x.item_count} items
              </span>
            </Link>
          ))
        ) : items ? (
          <EmptyState
            title="No evidence packages"
            description="Create a package through the governance API or workflow."
          />
        ) : (
          <p>Loading evidence packages…</p>
        )}
      </SectionCard>
    </PageShell>
  );
}
