import { useState } from 'react';
import { Save } from 'lucide-react';
import type { ApiEndpoint, ApiExpectedAccess, ApiObjectScope, ApiRole, AuthorizationMatrixEntry } from '../../../types';
import { AccessDecisionBadge } from './AccessDecisionBadge';
import { ObjectScopeBadge } from './ObjectScopeBadge';
import { RoleBadge } from './RoleBadge';

type CellDraft = Pick<AuthorizationMatrixEntry, 'expected_access' | 'object_scope' | 'expected_conditions' | 'analyst_notes' | 'review_status'>;

export function MatrixGrid({ endpoints, roles, entries, onSave }: { endpoints: ApiEndpoint[]; roles: ApiRole[]; entries: AuthorizationMatrixEntry[]; onSave: (endpointId: number, roleId: number, entry: AuthorizationMatrixEntry | undefined, draft: CellDraft) => Promise<void> }) {
  const [saving, setSaving] = useState<string | null>(null);
  const cell = (endpointId: number, roleId: number) => entries.find(item => item.endpoint_id === endpointId && item.role_id === roleId);

  return <div className="overflow-x-auto rounded-md border border-border">
    <table className="w-full min-w-[900px] text-left text-sm">
      <thead className="bg-muted/50"><tr><th className="sticky left-0 z-10 min-w-[260px] bg-muted px-3 py-3">Endpoint</th>{roles.map(role => <th key={role.id} className="min-w-[210px] px-3 py-3"><RoleBadge role={role} /></th>)}</tr></thead>
      <tbody className="divide-y divide-border">{endpoints.map(endpoint => <tr key={endpoint.id} className="align-top">
        <td className="sticky left-0 z-10 bg-card px-3 py-4"><span className="mr-2 font-semibold text-indigo-200">{endpoint.method}</span><span className="break-all font-mono text-xs">{endpoint.path}</span></td>
        {roles.map(role => <MatrixCell key={role.id} entry={cell(endpoint.id, role.id)} saving={saving === `${endpoint.id}-${role.id}`} onSave={async draft => { const key = `${endpoint.id}-${role.id}`; setSaving(key); try { await onSave(endpoint.id, role.id, cell(endpoint.id, role.id), draft); } finally { setSaving(null); } }} />)}
      </tr>)}</tbody>
    </table>
  </div>;
}

function MatrixCell({ entry, saving, onSave }: { entry?: AuthorizationMatrixEntry; saving: boolean; onSave: (draft: CellDraft) => Promise<void> }) {
  const [access, setAccess] = useState<ApiExpectedAccess>(entry?.expected_access || 'unknown');
  const [scope, setScope] = useState<ApiObjectScope>(entry?.object_scope || 'unknown');
  const [status, setStatus] = useState<AuthorizationMatrixEntry['review_status']>(entry?.review_status || 'not_reviewed');
  const [notes, setNotes] = useState(entry?.analyst_notes || '');
  const [condition, setCondition] = useState(typeof entry?.expected_conditions?.analyst_condition === 'string' ? entry.expected_conditions.analyst_condition : '');
  return <td className="px-3 py-3"><details><summary className="flex cursor-pointer list-none flex-wrap items-center gap-2"><AccessDecisionBadge access={entry?.expected_access || access} /><ObjectScopeBadge scope={entry?.object_scope || scope} /></summary><div className="mt-3 space-y-2">
    <select aria-label="Expected access" value={access} onChange={event => setAccess(event.target.value as ApiExpectedAccess)} className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs">{['allow', 'deny', 'conditional', 'unknown'].map(value => <option key={value}>{value}</option>)}</select>
    <select aria-label="Object scope" value={scope} onChange={event => setScope(event.target.value as ApiObjectScope)} className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs">{['own', 'assigned', 'tenant', 'organization', 'global', 'unknown'].map(value => <option key={value}>{value}</option>)}</select>
    <select aria-label="Review status" value={status} onChange={event => setStatus(event.target.value as AuthorizationMatrixEntry['review_status'])} className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs">{['not_reviewed', 'reviewed', 'requires_validation'].map(value => <option key={value}>{value.replaceAll('_', ' ')}</option>)}</select>
    <input aria-label="Expected condition" value={condition} onChange={event => setCondition(event.target.value)} placeholder="Expected condition" className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs" />
    <textarea aria-label="Analyst notes" value={notes} onChange={event => setNotes(event.target.value)} rows={2} placeholder="Analyst notes" className="w-full rounded-md border border-border bg-background px-2 py-2 text-xs" />
    <button type="button" disabled={saving} onClick={() => void onSave({ expected_access: access, object_scope: scope, expected_conditions: condition ? { ...(entry?.expected_conditions || {}), analyst_condition: condition } : entry?.expected_conditions || null, review_status: status, analyst_notes: notes || null })} className="inline-flex h-8 items-center gap-2 rounded-md bg-indigo-500 px-3 text-xs font-semibold text-white disabled:opacity-50"><Save className="h-3.5 w-3.5" />{saving ? 'Saving' : 'Save cell'}</button>
  </div></details></td>;
}
