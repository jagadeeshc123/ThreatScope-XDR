import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Database, Network, Plus, ShieldAlert } from 'lucide-react';
import type { ApiSecurityOverview as ApiSecurityOverviewType } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, StatCard } from '../../components/ui';
import { ApiAssessmentCard } from './components/ApiAssessmentCard';

export function ApiSecurityOverview() {
  const [overview, setOverview] = useState<ApiSecurityOverviewType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    vulnscopeApi.getApiSecurityOverview()
      .then(data => { if (!cancelled) setOverview(data); })
      .catch(() => { if (!cancelled) setError('API Security data could not be loaded.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <PageShell><div className="text-muted-foreground">Loading API Security...</div></PageShell>;
  if (error || !overview) return <PageShell><EmptyState title="API Security unavailable" description={error || 'No overview data was returned.'} /></PageShell>;

  return (
    <PageShell>
      <PageHeader
        title="API Security"
        subtitle="Create passive API assessments, import OpenAPI or Postman definitions, and inventory endpoints without executing requests."
        actions={
          <Link to="/api-security/new" className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white transition-colors hover:bg-indigo-400">
            <Plus className="h-4 w-4" /> New Assessment
          </Link>
        }
      />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Assessments" value={overview.total_assessments} detail="API workspaces" icon={<Network className="h-5 w-5" />} tone="info" />
        <StatCard label="Endpoints" value={overview.endpoints_inventoried} detail="Imported records" icon={<Database className="h-5 w-5" />} tone="default" />
        <StatCard label="Unauthenticated" value={overview.unauthenticated_endpoints} detail="No auth declared" icon={<ShieldAlert className="h-5 w-5" />} tone="warn" />
        <StatCard label="High Risk" value={overview.high_risk_endpoints} detail="Passive metadata signals" icon={<ShieldAlert className="h-5 w-5" />} tone="danger" />
      </div>

      {overview.recent_assessments.length ? (
        <div className="grid gap-4 lg:grid-cols-2">
          {overview.recent_assessments.map(assessment => <ApiAssessmentCard key={assessment.id} assessment={assessment} />)}
        </div>
      ) : (
        <EmptyState
          title="No API assessments yet"
          description="Create an assessment and import an OpenAPI or Postman file to build the first endpoint inventory."
          icon={<Network className="h-8 w-8" />}
          action={<Link to="/api-security/new" className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white hover:bg-indigo-400">Create assessment <ArrowRight className="h-4 w-4" /></Link>}
        />
      )}
    </PageShell>
  );
}

