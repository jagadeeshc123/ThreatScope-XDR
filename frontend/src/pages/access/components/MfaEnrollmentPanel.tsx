import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound, LoaderCircle, RotateCcw, ShieldCheck, ShieldOff, X } from 'lucide-react';
import { toast } from 'sonner';
import { mfaApi, type MfaStatus } from '../../../api/mfa';
import { PasswordField } from './PasswordField';
import { RecoveryCodesPanel } from './RecoveryCodesPanel';
import { TotpEnrollmentDialog } from './TotpEnrollmentDialog';

type MfaAction = 'disable' | 'regenerate';

function MfaActionDialog({ action, onClose, onDone }: { action: MfaAction | null; onClose: () => void; onDone: () => Promise<void> }) {
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[]>([]);

  useEffect(() => { setPassword(''); setCode(''); setRecovery(false); setConfirmed(false); setError(null); setCodes([]); }, [action]);
  if (!action) return null;
  const validFactor = recovery ? code.trim().length >= 4 : /^\d{6}$/.test(code);

  const submit = async () => {
    if (busy || !password || !validFactor || action === 'disable' && !confirmed) return;
    setBusy(true); setError(null);
    try {
      if (action === 'disable') {
        await mfaApi.disable(password, code, recovery);
        toast.success('MFA disabled. Other active sessions were revoked.');
        await onDone(); onClose();
      } else {
        const response = await mfaApi.regenerateRecoveryCodes(password, code, false);
        setPassword(''); setCode(''); setCodes(response.recovery_codes);
      }
    } catch {
      setError(action === 'disable' ? 'MFA could not be disabled. Check your password and verification code.' : 'Recovery codes could not be regenerated. Check your password and current TOTP code.');
    } finally { setBusy(false); }
  };

  return <div className="fixed inset-0 z-[90] grid place-items-center overflow-y-auto bg-black/75 p-4" role="dialog" aria-modal="true" aria-label={action === 'disable' ? 'Disable MFA' : 'Regenerate recovery codes'}>
    <div className="w-full max-w-lg rounded-xl border border-border bg-card p-6 shadow-2xl">
      <div className="flex justify-between gap-4"><div><h2 className="text-lg font-semibold">{action === 'disable' ? 'Disable MFA' : 'Regenerate recovery codes'}</h2><p className="mt-1 text-sm text-muted-foreground">{action === 'disable' ? 'This reduces account protection and revokes other active sessions.' : 'All previous recovery codes will immediately become invalid.'}</p></div>{!codes.length && <button type="button" disabled={busy} onClick={onClose} aria-label="Close" className="rounded p-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><X className="h-5 w-5" /></button>}</div>
      {codes.length ? <div className="mt-5"><RecoveryCodesPanel codes={codes} busy={busy} onAcknowledge={() => { setCodes([]); void onDone().then(() => { toast.success('Recovery codes regenerated.'); onClose(); }); }} /></div> : <div className="mt-5 space-y-4">
        <PasswordField label="Current password" value={password} onChange={setPassword} />
        {action === 'disable' && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={recovery} onChange={event => { setRecovery(event.target.checked); setCode(''); }} />Use a recovery code instead</label>}
        <label className="block text-sm font-medium">{recovery ? 'Unused recovery code' : 'Current six-digit authenticator code'}<input inputMode={recovery ? 'text' : 'numeric'} autoComplete="one-time-code" maxLength={recovery ? 64 : 6} value={code} onChange={event => setCode(recovery ? event.target.value.trim().slice(0, 64) : event.target.value.replace(/\D/g, '').slice(0, 6))} className="mt-2 block w-full rounded-md border border-border bg-background px-3 py-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary" /></label>
        {action === 'disable' && <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} className="mt-0.5" /><span>I understand that disabling MFA reduces account protection.</span></label>}
        {error && <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">{error}</p>}
        <div className="flex flex-wrap gap-3"><button type="button" disabled={busy || !password || !validFactor || action === 'disable' && !confirmed} onClick={() => void submit()} className={`inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold text-white disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${action === 'disable' ? 'bg-red-600' : 'bg-primary'}`}>{busy && <LoaderCircle className="h-4 w-4 animate-spin" />}{action === 'disable' ? 'Disable MFA' : 'Replace recovery codes'}</button><button type="button" disabled={busy} onClick={onClose} className="rounded-md border border-border px-4 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">Cancel</button></div>
      </div>}
    </div>
  </div>;
}

export function MfaEnrollmentPanel({ enabled, onChanged, compact = false }: { enabled: boolean; onChanged: () => Promise<void>; compact?: boolean }) {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [enrollmentOpen, setEnrollmentOpen] = useState(false);
  const [restart, setRestart] = useState(false);
  const [action, setAction] = useState<MfaAction | null>(null);

  const loadStatus = useCallback(async () => {
    setLoading(true); setError(null);
    try { setStatus(await mfaApi.getStatus()); }
    catch { setError('MFA status could not be loaded.'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void loadStatus(); }, [loadStatus]);

  const refresh = async () => { await onChanged(); await loadStatus(); };
  const openEnrollment = (shouldRestart: boolean) => { setRestart(shouldRestart); setEnrollmentOpen(true); };
  const cancelPending = async () => {
    if (!window.confirm('Cancel the incomplete MFA setup? No confirmed MFA device will be changed.')) return;
    try { await mfaApi.cancelEnrollment(); toast.success('Incomplete MFA setup cancelled.'); await loadStatus(); }
    catch { toast.error('Incomplete MFA setup could not be cancelled.'); }
  };

  if (loading && !status) return <p className="inline-flex items-center gap-2 text-sm text-muted-foreground"><LoaderCircle className="h-4 w-4 animate-spin" />Loading MFA status…</p>;
  const isEnabled = status?.enabled ?? enabled;
  const pending = !!status?.setup_incomplete && !isEnabled;

  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><p className="text-sm">MFA status: <strong className={isEnabled ? 'text-emerald-400' : pending ? 'text-amber-300' : ''}>{isEnabled ? 'Enabled' : pending ? 'Setup incomplete' : 'Disabled'}</strong></p>{isEnabled && <ShieldCheck className="h-5 w-5 text-emerald-400" />}</div>
    {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
    {!isEnabled && !pending && <><p className="text-sm leading-6 text-muted-foreground">Protect your account with time-based codes from an authenticator app.</p><button type="button" onClick={() => openEnrollment(false)} className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><KeyRound className="h-4 w-4" />Begin TOTP enrollment</button></>}
    {pending && <><p className="text-sm text-muted-foreground">A pending authenticator setup has not yet been verified.</p><div className="flex flex-wrap gap-2"><button type="button" onClick={() => openEnrollment(false)} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">Continue setup</button><button type="button" onClick={() => openEnrollment(true)} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><RotateCcw className="h-4 w-4" />Restart setup</button><button type="button" onClick={() => void cancelPending()} className="rounded-md border border-border px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">Cancel setup</button></div></>}
    {isEnabled && status && <><dl className="grid gap-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Method</dt><dd>{status.method}</dd></div><div><dt className="text-muted-foreground">Enrolled</dt><dd>{status.enrolled_at ? new Date(status.enrolled_at).toLocaleString() : 'Unknown'}</dd></div><div><dt className="text-muted-foreground">Last used</dt><dd>{status.last_used_at ? new Date(status.last_used_at).toLocaleString() : 'Not used yet'}</dd></div><div><dt className="text-muted-foreground">Recovery codes</dt><dd>{status.recovery_codes_remaining} remaining</dd></div></dl>{compact ? <Link to="/profile/security" className="inline-block text-sm font-semibold text-primary hover:underline">Manage in Security settings</Link> : <div className="flex flex-wrap gap-2"><button type="button" onClick={() => setAction('regenerate')} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><RotateCcw className="h-4 w-4" />Regenerate recovery codes</button><button type="button" onClick={() => setAction('disable')} className="inline-flex items-center gap-2 rounded-md border border-red-500/50 px-3 py-2 text-sm text-red-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400"><ShieldOff className="h-4 w-4" />Disable MFA</button></div>}</>}
    <TotpEnrollmentDialog open={enrollmentOpen} restart={restart} onClose={() => setEnrollmentOpen(false)} onCompleted={refresh} />
    <MfaActionDialog action={action} onClose={() => setAction(null)} onDone={refresh} />
  </div>;
}
