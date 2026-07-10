import type { ApiExpectedAccess } from '../../../types';

export function AccessDecisionBadge({ access }: { access: ApiExpectedAccess }) {
  const tone = access === 'allow' ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-200' : access === 'deny' ? 'border-red-400/40 bg-red-500/10 text-red-200' : access === 'conditional' ? 'border-amber-400/40 bg-amber-500/10 text-amber-100' : 'border-border bg-muted text-muted-foreground';
  return <span className={`inline-flex rounded-full border px-2 py-1 text-xs font-semibold capitalize ${tone}`}>{access}</span>;
}
