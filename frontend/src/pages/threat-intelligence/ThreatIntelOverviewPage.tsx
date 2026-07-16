import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Radar, ShieldAlert, ListChecks, Activity } from 'lucide-react';
import { threatIntelApi, type ThreatOverview } from '../../api/threatIntel';
import { PageHeader, PageShell, SectionCard, StatCard } from '../../components/ui';
import { SightingModuleBadge } from './components';
import { useAuth } from '../../auth/useAuth';

export function ThreatIntelOverviewPage() {
  const { can } = useAuth();
  const [data, setData] = useState<ThreatOverview | null>(null); const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  const load = () => threatIntelApi.overview().then(setData).catch(() => setError('Unable to load threat-intelligence overview.'));
  useEffect(() => { void load(); }, []);
  const run = async () => { setBusy(true); try { await threatIntelApi.runCorrelation(); await load(); } finally { setBusy(false); } };
  return <PageShell><PageHeader title="Threat Intelligence" subtitle="Offline IOC management and deterministic correlation against data already stored in ThreatScope XDR." actions={<div className="flex gap-2">{can('threat_intel:manage')&&<Link to="/threat-intelligence/indicators/new" className="rounded bg-muted px-3 py-2">Add indicator</Link>}{can('threat_intel:correlate')&&<button disabled={busy} onClick={() => void run()} className="rounded bg-primary px-3 py-2 disabled:opacity-50">Run stored-data correlation</button>}</div>} />
    <div className="rounded border border-cyan-500/30 bg-cyan-500/5 p-4 text-sm">Offline-only: this module performs no DNS resolution, URL fetching, reputation lookup, or active blocking.</div>
    {error && <p className="text-destructive">{error}</p>}{!data ? <p>Loading intelligence metrics…</p> : <><div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4"><StatCard label="Active indicators" value={data.total_active_indicators} icon={<Radar className="h-5 w-5" />} /><StatCard label="Active watchlists" value={data.active_watchlists} icon={<ListChecks className="h-5 w-5" />} /><StatCard label="New matches" value={data.new_matches} icon={<Activity className="h-5 w-5" />} tone="info" /><StatCard label="High-risk matches" value={data.high_risk_matches} icon={<ShieldAlert className="h-5 w-5" />} tone="danger" /></div><div className="grid gap-4 lg:grid-cols-2"><SectionCard title="Indicators by type"><Distribution data={data.indicators_by_type} /></SectionCard><SectionCard title="Severity distribution"><Distribution data={data.severity_distribution} /></SectionCard><SectionCard title="Confidence distribution"><Distribution data={data.confidence_distribution} /></SectionCard><SectionCard title="Sightings by module"><div className="space-y-2">{Object.entries(data.module_distribution).map(([key,value]) => <div key={key} className="flex justify-between"><SightingModuleBadge module={key} /><span>{value}</span></div>)}</div></SectionCard></div></>}</PageShell>;
}
function Distribution({ data }: { data: Record<string, number> }) { return <div className="space-y-2">{Object.entries(data).map(([key,value]) => <div key={key} className="flex justify-between rounded bg-muted p-2"><span className="capitalize">{key.replaceAll('_',' ')}</span><strong>{value}</strong></div>)}</div>; }
