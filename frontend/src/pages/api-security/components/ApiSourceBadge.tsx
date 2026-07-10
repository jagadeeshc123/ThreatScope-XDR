import clsx from 'clsx';
import type { ApiSourceType } from '../../../types';

export function ApiSourceBadge({ source }: { source: ApiSourceType }) {
  const classes = {
    openapi: 'border-indigo-400/50 bg-indigo-500/15 text-indigo-100',
    postman: 'border-violet-400/50 bg-violet-500/15 text-violet-100',
    manual: 'border-slate-400/40 bg-slate-500/15 text-slate-200',
  }[source];
  const label = source === 'openapi' ? 'OpenAPI' : source === 'postman' ? 'Postman' : 'Manual';

  return <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold leading-none', classes)}>{label}</span>;
}

