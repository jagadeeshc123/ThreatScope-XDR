import { useState } from 'react';

const availableRoles = [
  ['registered_user', 'Registered User'],
  ['security_analyst', 'Security Analyst'],
  ['auditor', 'Auditor'],
  ['executive_viewer', 'Executive Viewer'],
  ['administrator', 'Administrator'],
] as const;

export function AccountApprovalDialog({ open, onClose, onApprove }: { open: boolean; onClose: () => void; onApprove: (roles: string[], confirmAdmin: boolean) => Promise<void> }) {
  const [roles, setRoles] = useState<string[]>(['registered_user']);
  const [confirmAdmin, setConfirmAdmin] = useState(false);
  const [busy, setBusy] = useState(false);
  if (!open) return null;

  const toggleRole = (role: string, checked: boolean) => {
    setRoles(current => checked ? [...new Set([...current, role])] : current.filter(item => item !== role));
    if (role === 'administrator' && !checked) setConfirmAdmin(false);
  };

  return <div className="fixed inset-0 z-[90] grid place-items-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Approve registration"><div className="w-full max-w-md rounded-lg border bg-card p-6"><h2 className="text-lg font-semibold">Approve registration</h2><p className="mt-2 text-sm text-muted-foreground">Registered User is the safe limited default. Select only the roles this account needs.</p><fieldset className="mt-4 space-y-2"><legend className="text-sm font-medium">Roles</legend>{availableRoles.map(([key, name]) => <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={roles.includes(key)} onChange={event => toggleRole(key, event.target.checked)} />{name}</label>)}</fieldset>{roles.includes('administrator') && <label className="mt-3 flex gap-2 text-sm"><input type="checkbox" checked={confirmAdmin} onChange={event => setConfirmAdmin(event.target.checked)} />I explicitly confirm Administrator access.</label>}<div className="mt-5 flex gap-3"><button disabled={busy || roles.length === 0 || roles.includes('administrator') && !confirmAdmin} onClick={() => { setBusy(true); void onApprove(roles, confirmAdmin).finally(() => setBusy(false)); }} className="rounded bg-primary px-4 py-2 font-semibold text-primary-foreground disabled:opacity-50">Approve</button><button onClick={onClose}>Cancel</button></div></div></div>;
}
