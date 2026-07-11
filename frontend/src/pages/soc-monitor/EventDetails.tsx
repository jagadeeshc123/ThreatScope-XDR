import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import type { SocEvent } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { EmptyState, PageShell, SectionCard } from '../../components/ui';
import { AlertSeverityBadge } from './components/AlertSeverityBadge';
import { EventTypeBadge } from './components/EventTypeBadge';

export function EventDetails() {
  const { eventId } = useParams();
  const [event, setEvent] = useState<SocEvent | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => { vulnscopeApi.getSocEvent(Number(eventId)).then(setEvent).catch(() => setError(true)); }, [eventId]);
  if (error) return <PageShell><EmptyState title="Event unavailable" description="The event does not exist or could not be loaded." /></PageShell>;
  if (!event) return <PageShell>Loading event...</PageShell>;
  return <PageShell><Link to="/soc/events" className="text-sm text-primary">← Event Explorer</Link><div className="flex flex-wrap items-center gap-3"><h1 className="text-3xl font-bold">Event #{event.id}</h1><EventTypeBadge type={event.event_type} /><AlertSeverityBadge severity={event.severity} /></div><div className="grid gap-5 xl:grid-cols-2"><SectionCard title="Event Metadata"><dl className="grid grid-cols-2 gap-4 text-sm"><DT label="Time" value={new Date(event.event_time).toLocaleString()} /><DT label="Outcome" value={event.outcome || 'unknown'} /><DT label="Source IP" value={event.source_ip || '—'} /><DT label="Destination IP" value={event.destination_ip || '—'} /><DT label="Username" value={event.username || '—'} /><DT label="Source / Import" value={`${event.source_id} / ${event.import_id || 'none'}`} /></dl></SectionCard><SectionCard title="Redacted Raw Preview"><pre className="whitespace-pre-wrap break-all text-xs text-muted-foreground">{event.raw_preview_redacted || 'No preview available.'}</pre></SectionCard></div><SectionCard title="Normalized JSON"><pre className="overflow-auto whitespace-pre-wrap break-all rounded-md bg-background p-4 text-xs">{JSON.stringify(event.normalized_json, null, 2)}</pre></SectionCard></PageShell>;
}
function DT({ label, value }: { label: string; value: string }) { return <div><dt className="text-muted-foreground">{label}</dt><dd className="mt-1 font-medium">{value}</dd></div>; }
