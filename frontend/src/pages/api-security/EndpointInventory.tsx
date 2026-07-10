import { useEffect, useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { ArrowLeft, Search } from 'lucide-react';
import type { ApiEndpoint } from '../../types';
import { vulnscopeApi, type ApiEndpointFilters } from '../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard } from '../../components/ui';
import { EndpointTable } from './components/EndpointTable';

export function EndpointInventory() {
  const { assessmentId } = useParams();
  const [searchParams] = useSearchParams();
  const numericId = Number(assessmentId);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [method, setMethod] = useState('');
  const [auth, setAuth] = useState('');
  const [deprecated, setDeprecated] = useState('');
  const [risk, setRisk] = useState('');
  const [tag, setTag] = useState('');
  const [query, setQuery] = useState(searchParams.get('q') || '');
  const [sort, setSort] = useState<ApiEndpointFilters['sort']>('path');

  useEffect(() => {
    if (!numericId) return;
    let cancelled = false;
    setLoading(true);
    const filters: ApiEndpointFilters = {
      method: method || undefined,
      auth: auth as ApiEndpointFilters['auth'] || undefined,
      deprecated: deprecated === '' ? undefined : deprecated === 'true',
      risk: risk as ApiEndpointFilters['risk'] || undefined,
      tag: tag || undefined,
      q: query || undefined,
      sort,
    };
    vulnscopeApi.listApiEndpoints(numericId, filters)
      .then(data => { if (!cancelled) setEndpoints(data); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [numericId, method, auth, deprecated, risk, tag, query, sort]);

  const tags = useMemo(() => Array.from(new Set(endpoints.flatMap(endpoint => endpoint.tags))).sort(), [endpoints]);

  return (
    <PageShell>
      <PageHeader
        title="Endpoint Inventory"
        subtitle="Filter and sort imported endpoint metadata from the selected API assessment."
        actions={<Link to={`/api-security/assessments/${numericId}`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted"><ArrowLeft className="h-4 w-4" /> Assessment</Link>}
      />
      <SectionCard>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-7">
          <label className="text-xs font-semibold text-muted-foreground">Method<select value={method} onChange={event => setMethod(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"><option value="">All</option>{['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map(item => <option key={item}>{item}</option>)}</select></label>
          <label className="text-xs font-semibold text-muted-foreground">Auth<select value={auth} onChange={event => setAuth(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"><option value="">All</option><option value="authenticated">Authenticated</option><option value="unauthenticated">Unauthenticated</option></select></label>
          <label className="text-xs font-semibold text-muted-foreground">Deprecated<select value={deprecated} onChange={event => setDeprecated(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"><option value="">All</option><option value="true">Deprecated</option><option value="false">Current</option></select></label>
          <label className="text-xs font-semibold text-muted-foreground">Risk<select value={risk} onChange={event => setRisk(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"><option value="">All</option>{['info', 'low', 'medium', 'high'].map(item => <option key={item} value={item}>{item}</option>)}</select></label>
          <label className="text-xs font-semibold text-muted-foreground">Tag<input list="api-tags" value={tag} onChange={event => setTag(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground" /><datalist id="api-tags">{tags.map(item => <option key={item} value={item} />)}</datalist></label>
          <label className="text-xs font-semibold text-muted-foreground">Sort<select value={sort} onChange={event => setSort(event.target.value as ApiEndpointFilters['sort'])} className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"><option value="path">Path</option><option value="method">Method</option><option value="authentication">Authentication</option><option value="risk">Risk</option></select></label>
          <label className="text-xs font-semibold text-muted-foreground">Search<div className="mt-1 flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2"><Search className="h-4 w-4 text-muted-foreground" /><input value={query} onChange={event => setQuery(event.target.value)} className="min-w-0 flex-1 bg-transparent text-sm text-foreground outline-none" /></div></label>
        </div>
      </SectionCard>
      <SectionCard title="Endpoints" subtitle={loading ? 'Loading...' : `${endpoints.length} matching records`}>
        {loading ? <div className="text-sm text-muted-foreground">Loading endpoints...</div> : endpoints.length ? <EndpointTable endpoints={endpoints} /> : <EmptyState title="No endpoints match" description="Adjust filters or import an API definition for this assessment." />}
      </SectionCard>
    </PageShell>
  );
}
