import { useAuth } from '../../../auth/useAuth';
import { useNavigate } from 'react-router-dom';

export function SessionExpiryModal() {
  const navigate = useNavigate();
  const { clearExpiredSession } = useAuth();

  const returnToLogin = () => {
    clearExpiredSession();
    navigate('/login', { replace: true });
  };

  return <div className="fixed inset-0 z-[100] grid min-h-screen place-items-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Session expired"><div className="max-w-sm rounded-lg border border-border bg-card p-6 text-center shadow-2xl"><h2 className="text-lg font-semibold">Session expired</h2><p className="mt-2 text-sm text-muted-foreground">Your secure session ended or was revoked. Sign in again to continue.</p><button type="button" onClick={returnToLogin} className="mt-5 inline-flex rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Return to login</button></div></div>;
}
