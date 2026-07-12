import { useEffect, useState } from "react";
import type { RiskException } from "../../types";
import { vulnscopeApi } from "../../api/vulnscope";
import {
  EmptyState,
  PageHeader,
  PageShell,
  SectionCard,
} from "../../components/ui";
import { RiskExceptionPanel } from "./components/RiskExceptionPanel";
export function ExceptionRegister() {
  const [items, setItems] = useState<RiskException[] | null>(null),
    [summary, setSummary] = useState("");
  const load = () => vulnscopeApi.listGovernanceExceptions().then(setItems);
  useEffect(() => {
    void load();
  }, []);
  const check = async () => {
    const r = await vulnscopeApi.checkGovernanceExceptions();
    setSummary(JSON.stringify(r, null, 2));
    await load();
  };
  const change=async(item:RiskException,status:string)=>{const payload:Record<string,unknown>={status};if(status==='approved'){const approver=window.prompt('Approver name');const expires_at=window.prompt('Future expiration (ISO date)');if(!approver||!expires_at)return;payload.approver_name=approver;payload.expires_at=expires_at}await vulnscopeApi.updateGovernanceException(item.id,payload);await load()};
  return (
    <PageShell>
      <PageHeader
        title="Risk Exceptions"
        subtitle="Explicit, time-limited analyst decisions; no automatic approval."
        actions={
          <button
            onClick={() => void check()}
            className="rounded bg-primary px-3 py-2"
          >
            Check Expired Exceptions
          </button>
        }
      />
      {summary && <pre className="rounded bg-muted p-3 text-xs">{summary}</pre>}
      <SectionCard>
        {items?.length ? (
          <><RiskExceptionPanel items={items}/>{items.map(x=><div key={x.id} className="mt-2 flex gap-2">{['approved','rejected','revoked'].map(s=><button key={s} onClick={()=>void change(x,s)} className="rounded bg-muted px-2 py-1 text-xs">{x.exception_key}: {s}</button>)}</div>)}</>
        ) : items ? (
          <EmptyState
            title="No risk exceptions"
            description="Request an exception from a risk record."
          />
        ) : (
          <p>Loading exceptions…</p>
        )}
      </SectionCard>
    </PageShell>
  );
}
