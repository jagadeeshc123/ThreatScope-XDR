import { useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';
import { toast } from 'sonner';

export function RecoveryCodesPanel({ codes, onAcknowledge, busy = false }: {
  codes: string[];
  onAcknowledge: () => void;
  busy?: boolean;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const text = `ThreatScope XDR MFA recovery codes\n\n${codes.join('\n')}\n`;

  const copyAll = async () => {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      toast.success('Recovery codes copied.');
    } catch {
      toast.error('Recovery codes could not be copied. Select them manually.');
    }
  };

  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'threatscope-mfa-recovery-codes.txt';
    anchor.click();
    URL.revokeObjectURL(url);
    toast.success('Recovery-code text file created in memory.');
  };

  return <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
    <h3 className="font-semibold text-amber-100">Recovery codes — shown once</h3>
    <p className="mt-1 text-sm text-muted-foreground">These recovery codes will not be shown again. Store them offline; each works once.</p>
    <div className="mt-4 grid grid-cols-1 gap-2 rounded-md border border-border bg-background p-4 font-mono text-sm sm:grid-cols-2" aria-label="Recovery codes">
      {codes.map(code => <code key={code}>{code}</code>)}
    </div>
    <div className="mt-4 flex flex-wrap gap-2 print:hidden">
      <button type="button" onClick={() => void copyAll()} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><Copy className="h-4 w-4" />Copy all</button>
      <button type="button" onClick={download} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><Download className="h-4 w-4" />Download text</button>
    </div>
    <label className="mt-5 flex items-start gap-3 text-sm">
      <input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} className="mt-0.5 h-4 w-4" />
      <span>I have saved my recovery codes.</span>
    </label>
    <button type="button" disabled={!acknowledged || busy} onClick={onAcknowledge} className="mt-4 inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
      <Check className="h-4 w-4" />{busy ? 'Finishing…' : 'Finish setup'}
    </button>
  </div>;
}
