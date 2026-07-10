import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import type { Scan } from '../types';
import { vulnscopeApi, type PolicyPack } from '../api/vulnscope';
import { EmptyState, PageHeader, PageShell, PolicyCard, StatCard } from '../components/ui';

export function Policies() {
  const [policies, setPolicies] = useState<PolicyPack[]>([]);
  const [latestCompletedScan, setLatestCompletedScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [apiPolicies, scans] = await Promise.all([vulnscopeApi.listPolicies(), vulnscopeApi.listScans()]);
      setPolicies(apiPolicies);
      setLatestCompletedScan(scans.find(scan => scan.status === 'completed') || null);
    } catch {
      setError('Policy packs could not be loaded from the backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadPolicies();
  }, [loadPolicies]);

  const checks = policies.reduce((total, policy) => total + policy.checks.length, 0);
  const highImpact = policies.reduce((total, policy) => total + policy.checks.filter(check => check.severity_impact === 'critical' || check.severity_impact === 'high').length, 0);

  return (
    <PageShell>
      <PageHeader
        title="Compliance Policies"
        subtitle="Configured web exposure baselines and browser hardening checks from the backend policy registry."
        actions={latestCompletedScan && <Link to={`/scans?highlight=${latestCompletedScan.id}&tab=policies`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted">Latest Scan Results <ArrowRight className="h-4 w-4" /></Link>}
      />

      {loading && <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">Loading policy packs...</div>}
      {!loading && error && <EmptyState title="Policies unavailable" description={error} action={<button onClick={() => void loadPolicies()} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Try Again</button>} />}

      {!loading && !error && (
        <>
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
            <EmptyState title="No policies configured" description="Add policy pack JSON files to the backend policy registry." />
          )}
        </>
      )}
    </PageShell>
  );
}
