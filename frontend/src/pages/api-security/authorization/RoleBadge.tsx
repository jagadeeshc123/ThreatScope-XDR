import type { ApiRole } from '../../../types';

export function RoleBadge({ role }: { role: ApiRole }) {
  const tone = role.privilege_level === 'admin' ? 'border-red-400/40 text-red-200' : role.privilege_level === 'public' ? 'border-slate-400/40 text-slate-200' : role.privilege_level === 'service' ? 'border-cyan-400/40 text-cyan-200' : 'border-indigo-400/40 text-indigo-200';
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`}>{role.name}</span>;
}
