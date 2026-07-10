import type { ApiObjectScope } from '../../../types';

export function ObjectScopeBadge({ scope }: { scope: ApiObjectScope }) {
  return <span className="inline-flex rounded-full border border-violet-400/30 bg-violet-500/10 px-2 py-1 text-xs capitalize text-violet-200">{scope}</span>;
}
