import { useState } from 'react';
import { Plus, Save, Trash2 } from 'lucide-react';
import type { ApiPrivilegeLevel, ApiRole } from '../../../types';
import { vulnscopeApi } from '../../../api/vulnscope';
import { RoleBadge } from './RoleBadge';

export function RoleManager({ assessmentId, roles, onChange }: { assessmentId: number; roles: ApiRole[]; onChange: () => Promise<void> }) {
  const [name, setName] = useState('');
  const [level, setLevel] = useState<ApiPrivilegeLevel>('user');
  const add = async () => { if (!name.trim()) return; await vulnscopeApi.createApiRole(assessmentId, { name: name.trim(), privilege_level: level }); setName(''); await onChange(); };
  return <div className="space-y-3"><div className="flex flex-wrap gap-2"><input value={name} onChange={event => setName(event.target.value)} placeholder="Role name" className="min-w-[150px] flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm" /><select value={level} onChange={event => setLevel(event.target.value as ApiPrivilegeLevel)} className="rounded-md border border-border bg-background px-3 py-2 text-sm">{['public', 'user', 'privileged', 'admin', 'service'].map(item => <option key={item}>{item}</option>)}</select><button onClick={() => void add()} title="Add role" className="inline-flex h-10 w-10 items-center justify-center rounded-md bg-indigo-500 text-white"><Plus className="h-4 w-4" /></button></div>
    <div className="space-y-2">{roles.map(role => <RoleRow key={role.id} role={role} onChange={onChange} />)}</div></div>;
}

function RoleRow({ role, onChange }: { role: ApiRole; onChange: () => Promise<void> }) {
  const [name, setName] = useState(role.name); const [level, setLevel] = useState<ApiPrivilegeLevel>(role.privilege_level);
  return <div className="rounded-md border border-border bg-background/50 p-3"><div className="mb-2"><RoleBadge role={role} /></div><div className="flex flex-wrap gap-2"><input aria-label="Role name" value={name} onChange={event => setName(event.target.value)} className="min-w-[120px] flex-1 rounded-md border border-border bg-background px-2 py-2 text-xs" /><select aria-label="Privilege level" value={level} onChange={event => setLevel(event.target.value as ApiPrivilegeLevel)} className="rounded-md border border-border bg-background px-2 py-2 text-xs">{['public', 'user', 'privileged', 'admin', 'service'].map(item => <option key={item}>{item}</option>)}</select><button onClick={() => void vulnscopeApi.updateApiRole(role.id, { name, privilege_level: level }).then(onChange)} title="Save role" className="rounded-md p-2 text-indigo-200 hover:bg-indigo-500/10"><Save className="h-4 w-4" /></button><button onClick={() => void vulnscopeApi.deleteApiRole(role.id).then(onChange)} title="Delete role" className="rounded-md p-2 text-muted-foreground hover:bg-red-500/10 hover:text-red-200"><Trash2 className="h-4 w-4" /></button></div></div>;
}
