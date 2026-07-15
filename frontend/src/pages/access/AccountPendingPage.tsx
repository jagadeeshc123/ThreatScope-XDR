import { Link, useLocation } from 'react-router-dom';
import type { SafeAccount } from '../../api/access';
import { RegistrationStatusBadge } from './components/RegistrationStatusBadge';

export function AccountPendingPage() {
  const state = useLocation().state as { account?: SafeAccount; activated?: boolean } | null;
  const account = state?.account;
  const activated = state?.activated;
  return <main className="grid min-h-screen place-items-center bg-background p-5"><div className="w-full max-w-md rounded-xl border bg-card p-7 text-center"><RegistrationStatusBadge status={activated ? 'active' : 'pending_approval'} /><h1 className="mt-5 text-2xl font-semibold">{activated ? 'Account created' : 'Account awaiting approval'}</h1><p className="mt-3 text-sm leading-6 text-muted-foreground">{activated ? 'Your limited local account is active. Sign in with either identifier.' : 'A local administrator must approve the registration before protected modules are available.'}</p>{account && <dl className="mt-5 rounded border bg-background p-4 text-left text-sm"><dt className="text-muted-foreground">Account</dt><dd>{account.display_name} · {account.username}</dd><dt className="mt-2 text-muted-foreground">Email</dt><dd>{account.email}</dd></dl>}<Link to="/login" className="mt-6 inline-block rounded bg-primary px-4 py-2 font-semibold text-primary-foreground">Return to Sign In</Link></div></main>;
}
