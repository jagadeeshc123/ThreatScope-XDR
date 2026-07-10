import { useState } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import type { ApiIdentity, ApiRole } from '../../../types';
import { vulnscopeApi } from '../../../api/vulnscope';

export function IdentityManager({ assessmentId, identities, roles, onChange }: { assessmentId: number; identities: ApiIdentity[]; roles: ApiRole[]; onChange: () => Promise<void> }) {
  const [label, setLabel] = useState('');
  const [roleId, setRoleId] = useState<number | null>(roles[0]?.id || null);
  const add = async () => { if (!label.trim()) return; await vulnscopeApi.createApiIdentity(assessmentId, { label: label.trim(), role_id: roleId, identity_type: 'custom' }); setLabel(''); await onChange(); };
  return <div className="space-y-3"><div className="flex flex-wrap gap-2"><input value={label} onChange={event => setLabel(event.target.value)} placeholder="Identity label only" className="min-w-[150px] flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm" /><select value={roleId || ''} onChange={event => setRoleId(Number(event.target.value) || null)} className="rounded-md border border-border bg-background px-3 py-2 text-sm"><option value="">No role</option>{roles.map(role => <option key={role.id} value={role.id}>{role.name}</option>)}</select><button onClick={() => void add()} title="Add identity" className="inline-flex h-10 w-10 items-center justify-center rounded-md bg-indigo-500 text-white"><Plus className="h-4 w-4" /></button></div>
    <p className="text-xs text-muted-foreground">Labels and role mappings only. Credentials and tokens are never stored.</p><div className="space-y-2">{identities.map(identity => <div key={identity.id} className="flex items-center justify-between rounded-md border border-border bg-background/50 p-3"><div><div className="text-sm font-semibold">{identity.label}</div><div className="text-xs text-muted-foreground">{roles.find(role => role.id === identity.role_id)?.name || 'No role'} | {identity.identity_type}</div></div><button onClick={() => void vulnscopeApi.deleteApiIdentity(identity.id).then(onChange)} title="Delete identity" className="rounded-md p-2 text-muted-foreground hover:bg-red-500/10 hover:text-red-200"><Trash2 className="h-4 w-4" /></button></div>)}</div></div>;
}
