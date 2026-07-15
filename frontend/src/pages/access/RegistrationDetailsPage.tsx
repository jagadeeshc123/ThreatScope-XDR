import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import { accessApi, type RegistrationRecord } from '../../api/access';
import { PageHeader, PageShell, SectionCard } from '../../components/ui';
import { RoleBadge } from './components/RoleBadge';
import { RegistrationStatusBadge } from './components/RegistrationStatusBadge';
import { RegistrationSourceBadge } from './components/RegistrationSourceBadge';
import { AccountApprovalDialog } from './components/AccountApprovalDialog';
import { AccountRejectionDialog } from './components/AccountRejectionDialog';

export function RegistrationDetailsPage() {
  const { userId } = useParams();
  const navigate = useNavigate();
  const [item, setItem] = useState<RegistrationRecord | null>(null);
  const [approveOpen, setApproveOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  const load = useCallback(async () => setItem(await accessApi.registration(Number(userId))), [userId]);
  useEffect(() => { void load().catch(() => navigate('/admin/registrations')); }, [load, navigate]);
  if (!item) return <PageShell><p>Loading registration...</p></PageShell>;

  const approve = async (roles: string[], confirmAdministrator: boolean) => {
    try {
      await accessApi.approve(item.id, roles, confirmAdministrator);
      setApproveOpen(false);
      toast.success('Registration approved');
      await load();
    } catch { toast.error('Registration could not be approved.'); }
  };
  const reject = async (reason: string) => {
    try {
      await accessApi.reject(item.id, reason);
      setRejectOpen(false);
      toast.success('Registration rejected');
      await load();
    } catch { toast.error('Registration could not be rejected.'); }
  };
  const reopen = async () => {
    if (!confirm('Return this rejected account to pending approval?')) return;
    try {
      await accessApi.reopen(item.id);
      toast.success('Registration reopened');
      await load();
    } catch { toast.error('Registration could not be reopened.'); }
  };

  const actions = <div className="flex gap-2">{['pending_approval', 'rejected'].includes(item.status) && <button onClick={() => setApproveOpen(true)} className="rounded bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Approve</button>}{['pending_approval', 'active'].includes(item.status) && <button onClick={() => setRejectOpen(true)} className="rounded border border-red-500/40 px-4 py-2 text-sm text-red-200">Reject</button>}{item.status === 'rejected' && <button onClick={() => void reopen()} className="rounded border px-4 py-2 text-sm">Reopen</button>}</div>;
  return <PageShell><PageHeader title={item.display_name} subtitle={`Registration for ${item.username}`} actions={actions} /><div className="grid gap-6 lg:grid-cols-2"><SectionCard title="Registration"><dl className="space-y-3 text-sm"><div><dt className="text-muted-foreground">Status</dt><dd className="mt-1"><RegistrationStatusBadge status={item.status} /></dd></div><div><dt className="text-muted-foreground">Source</dt><dd className="mt-1"><RegistrationSourceBadge source={item.registration_source} /></dd></div><div><dt className="text-muted-foreground">Safe email</dt><dd>{item.safe_email}</dd></div><div><dt className="text-muted-foreground">Email ownership</dt><dd>{item.email_verified ? 'Verified' : 'Not independently verified'}</dd></div></dl></SectionCard><SectionCard title="Assigned roles"><div className="flex flex-wrap gap-2">{item.roles.map(role => <RoleBadge key={role} role={role} />)}</div>{item.rejection_reason && <p className="mt-4 rounded border bg-background p-3 text-sm">Previous rejection: {item.rejection_reason}</p>}</SectionCard></div><AccountApprovalDialog open={approveOpen} onClose={() => setApproveOpen(false)} onApprove={approve} /><AccountRejectionDialog open={rejectOpen} onClose={() => setRejectOpen(false)} onReject={reject} /></PageShell>;
}
