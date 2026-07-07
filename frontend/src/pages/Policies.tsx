import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { getPolicies, type PolicyPack } from '../data/demoData';
import { EmptyState, PageHeader, PageShell, PolicyCard, StatCard } from '../components/ui';

export function Policies() {
  const [policies, setPolicies] = useState<PolicyPack[]>([]);

  useEffect(() => {
    setPolicies(getPolicies());
  }, []);

  const checks = policies.reduce((total, policy) => total + policy.checks.length, 0);
  const highImpact = policies.reduce((total, policy) => total + policy.checks.filter(check => check.severity_impact === 'critical' || check.severity_impact === 'high').length, 0);

  return (
    <PageShell>
      <PageHeader
        title="Compliance Policies"
        subtitle="Demo data. Web application exposure baselines and browser hardening checks grouped into readable policy packs."
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard label="Policy Packs" value={policies.length} icon={<ShieldCheck className="h-5 w-5" />} tone="good" />
        <StatCard label="Total Checks" value={checks} icon={<ShieldCheck className="h-5 w-5" />} tone="info" />
        <StatCard label="High Impact Checks" value={highImpact} icon={<ShieldCheck className="h-5 w-5" />} tone="danger" />
      </div>

      {policies.length > 0 ? (
        <div className="grid gap-5 lg:grid-cols-2">
          {policies.map(policy => <PolicyCard key={policy.policy_id} policy={policy} />)}
        </div>
      ) : (
        <EmptyState title="No policies yet" description="Policy packs will appear here when configured." />
      )}
    </PageShell>
  );
}
