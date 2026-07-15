import { Component, useEffect, useRef, useState, type ReactNode } from 'react';
import axios from 'axios';
import { CheckCircle2, Copy, LoaderCircle, ShieldCheck, X } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { toast } from 'sonner';
import { mfaApi, type MfaEnrollmentSetup } from '../../../api/mfa';
import { PasswordField } from './PasswordField';
import { RecoveryCodesPanel } from './RecoveryCodesPanel';

export type TotpEnrollmentState = 'idle' | 'starting' | 'setup_ready' | 'verifying' | 'recovery_codes' | 'completed' | 'cancelled' | 'error';

class QrCodeBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed
      ? <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-4 text-sm">The QR code could not be rendered. Use the manual setup key below.</p>
      : this.props.children;
  }
}

function enrollmentError(error: unknown, fallback: string) {
  if (!axios.isAxiosError(error)) return fallback;
  if (!error.response) return 'The server is unavailable. Try again when the connection is restored.';
  switch (error.response.status) {
    case 400: return 'The current password is incorrect.';
    case 403: return 'This account is not eligible for MFA setup, or the secure request could not be validated.';
    case 409: return 'This setup is no longer available. Restart MFA setup.';
    case 422: return 'That six-digit code is invalid. Wait for a new code and try again.';
    case 429: return 'Too many attempts. Restart MFA setup to continue.';
    case 503: return 'MFA setup is temporarily unavailable. Contact an administrator if this continues.';
    default: return fallback;
  }
}

export function TotpEnrollmentDialog({ open, restart = false, onClose, onCompleted }: {
  open: boolean;
  restart?: boolean;
  onClose: () => void;
  onCompleted: () => Promise<void>;
}) {
  const [phase, setPhase] = useState<TotpEnrollmentState>('idle');
  const [password, setPassword] = useState('');
  const [setup, setSetup] = useState<MfaEnrollmentSetup | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (!open) return;
    setPhase('idle');
    setPassword('');
    setSetup(null);
    setCode('');
    setRecoveryCodes([]);
    setError(null);
    requestAnimationFrame(() => headingRef.current?.focus());
  }, [open, restart]);

  if (!open) return null;
  const busy = phase === 'starting' || phase === 'verifying';

  const start = async () => {
    if (!password || busy) return;
    setPhase('starting');
    setError(null);
    try {
      setSetup(await mfaApi.startEnrollment(password, restart));
      setPassword('');
      setPhase('setup_ready');
    } catch (caught) {
      setError(enrollmentError(caught, 'MFA setup could not be started.'));
      setPhase('error');
    }
  };

  const verify = async () => {
    if (!setup || !/^\d{6}$/.test(code) || busy) return;
    setPhase('verifying');
    setError(null);
    try {
      const response = await mfaApi.confirmEnrollment(setup.device_id, code);
      setCode('');
      setSetup(null);
      setRecoveryCodes(response.recovery_codes);
      setPhase('recovery_codes');
    } catch (caught) {
      setError(enrollmentError(caught, 'MFA verification could not be completed.'));
      setPhase('setup_ready');
    }
  };

  const cancel = async () => {
    if (busy || phase === 'recovery_codes') return;
    try {
      if (setup) await mfaApi.cancelEnrollment();
      setSetup(null);
      setPhase('cancelled');
      toast.success('MFA setup cancelled.');
      onClose();
    } catch (caught) {
      setError(enrollmentError(caught, 'MFA setup could not be cancelled.'));
      setPhase('error');
    }
  };

  const acknowledge = async () => {
    setRecoveryCodes([]);
    setPhase('completed');
    await onCompleted();
    toast.success('Authenticator-app MFA is enabled.');
  };

  return <div className="fixed inset-0 z-[90] grid min-h-screen place-items-center overflow-y-auto bg-black/75 p-3 sm:p-6" role="dialog" aria-modal="true" aria-labelledby="totp-dialog-title">
    <div className="my-auto w-full max-w-2xl rounded-xl border border-border bg-card p-5 shadow-2xl sm:p-7">
      <div className="flex items-start justify-between gap-4">
        <div><h2 id="totp-dialog-title" ref={headingRef} tabIndex={-1} className="text-xl font-semibold outline-none">Set up authenticator app</h2><p className="mt-1 text-sm text-muted-foreground">Add ThreatScope XDR to a standard offline TOTP authenticator.</p></div>
        {phase !== 'recovery_codes' && <button type="button" disabled={busy} onClick={() => void cancel()} aria-label="Cancel MFA setup" className="rounded p-1 text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><X className="h-5 w-5" /></button>}
      </div>

      {(phase === 'idle' || phase === 'starting' || phase === 'error' && !setup) && <div className="mt-6 space-y-4">
        <p className="text-sm">Confirm your current password before creating an authenticator setup.</p>
        <PasswordField label="Current password" value={password} onChange={setPassword} />
        {error && <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">{error}</p>}
        <div className="flex flex-wrap gap-3">
          <button type="button" disabled={!password || busy} onClick={() => void start()} className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">{phase === 'starting' && <LoaderCircle className="h-4 w-4 animate-spin" />}{phase === 'starting' ? 'Starting…' : restart ? 'Restart setup' : 'Start setup'}</button>
          <button type="button" disabled={busy} onClick={() => void cancel()} className="rounded-md border border-border px-4 py-2 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">Cancel</button>
        </div>
      </div>}

      {setup && (phase === 'setup_ready' || phase === 'verifying' || phase === 'error') && <div className="mt-6 space-y-5">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-muted-foreground"><li>Open your authenticator app and add an account.</li><li>Scan this QR code, or enter the manual setup key.</li><li>Enter the current six-digit code below.</li></ol>
        <div className="grid gap-5 sm:grid-cols-[auto_1fr] sm:items-center">
          <div className="w-fit rounded-lg bg-white p-3">
            <QrCodeBoundary key={setup.provisioning_uri}><QRCodeSVG value={setup.provisioning_uri} size={190} level="M" title="ThreatScope XDR authenticator setup QR code" /></QrCodeBoundary>
          </div>
          <div className="min-w-0 space-y-2"><p className="text-xs uppercase tracking-wide text-muted-foreground">Manual setup key</p><code className="block break-all rounded-md border border-border bg-background p-3 font-mono text-sm" data-testid="manual-setup-key">{setup.manual_setup_key}</code><button type="button" onClick={() => void navigator.clipboard.writeText(setup.manual_setup_key).then(() => toast.success('Setup key copied.')).catch(() => toast.error('Copy failed. Select the key manually.'))} className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><Copy className="h-4 w-4" />Copy key</button><p className="text-xs text-muted-foreground">Issuer: {setup.issuer}<br />Account: {setup.account_label}</p></div>
        </div>
        <label className="block text-sm font-medium" htmlFor="totp-verification-code">Six-digit verification code</label>
        <input id="totp-verification-code" autoFocus inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={event => setCode(event.target.value.replace(/\s/g, '').replace(/\D/g, '').slice(0, 6))} onKeyDown={event => { if (event.key === 'Enter') void verify(); }} className="w-full max-w-xs rounded-md border border-border bg-background px-4 py-3 font-mono text-lg tracking-[0.35em] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary" />
        {error && <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">{error}</p>}
        <div className="flex flex-wrap gap-3"><button type="button" disabled={!/^\d{6}$/.test(code) || busy} onClick={() => void verify()} className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">{phase === 'verifying' ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}{phase === 'verifying' ? 'Verifying…' : 'Verify and Enable MFA'}</button><button type="button" disabled={busy} onClick={() => void cancel()} className="rounded-md border border-border px-4 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">Cancel</button></div>
      </div>}

      {phase === 'recovery_codes' && <div className="mt-6"><RecoveryCodesPanel codes={recoveryCodes} onAcknowledge={() => void acknowledge()} /></div>}
      {phase === 'completed' && <div className="mt-8 text-center"><CheckCircle2 className="mx-auto h-12 w-12 text-emerald-400" /><h3 className="mt-3 text-lg font-semibold">MFA enabled</h3><p className="mt-2 text-sm text-muted-foreground">Your authenticator app will be required the next time you sign in.</p><button type="button" onClick={onClose} className="mt-5 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">Close</button></div>}
    </div>
  </div>;
}
