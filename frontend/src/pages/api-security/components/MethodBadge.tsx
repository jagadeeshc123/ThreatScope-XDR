import clsx from 'clsx';

const METHOD_CLASSES: Record<string, string> = {
  GET: 'border-emerald-400/50 bg-emerald-500/15 text-emerald-200',
  POST: 'border-blue-400/50 bg-blue-500/15 text-blue-200',
  PUT: 'border-amber-400/50 bg-amber-500/15 text-amber-100',
  PATCH: 'border-purple-400/50 bg-purple-500/15 text-purple-100',
  DELETE: 'border-red-400/50 bg-red-500/15 text-red-200',
};

export function MethodBadge({ method }: { method: string }) {
  return (
    <span className={clsx('inline-flex min-w-16 justify-center rounded-md border px-2 py-1 font-mono text-xs font-bold', METHOD_CLASSES[method] || 'border-slate-400/40 bg-slate-500/15 text-slate-200')}>
      {method}
    </span>
  );
}

