import clsx from 'clsx';
import type { ApiRiskLevel } from '../../../types';

export function ApiRiskBadge({ risk }: { risk: ApiRiskLevel }) {
  const classes = {
    high: 'border-red-400/50 bg-red-500/15 text-red-200',
    medium: 'border-amber-400/50 bg-amber-500/15 text-amber-100',
    low: 'border-blue-400/50 bg-blue-500/15 text-blue-200',
    info: 'border-slate-400/40 bg-slate-500/15 text-slate-200',
  }[risk];

  return <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold capitalize leading-none', classes)}>{risk}</span>;
}

