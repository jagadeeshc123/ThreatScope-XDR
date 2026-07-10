import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Database, ShieldAlert } from 'lucide-react';
import type { ApiAssessment } from '../../../types';
import { StatusBadge } from '../../../components/ui';
import { ApiSourceBadge } from './ApiSourceBadge';

export function ApiAssessmentCard({ assessment }: { assessment: ApiAssessment }) {
  return (
    <article className="rounded-lg border border-border bg-card/90 p-5 shadow-sm shadow-black/10">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <ApiSourceBadge source={assessment.source_type} />
            <StatusBadge status={assessment.status} />
          </div>
          <h3 className="mt-3 text-lg font-semibold text-foreground">{assessment.name}</h3>
          {assessment.description && <p className="mt-2 line-clamp-2 text-sm leading-6 text-muted-foreground">{assessment.description}</p>}
        </div>
        <Link to={`/api-security/assessments/${assessment.id}`} className="rounded-md p-2 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground" title="Open assessment">
          <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
      <div className="mt-5 grid grid-cols-3 gap-3 text-sm">
        <Metric icon={<Database className="h-4 w-4" />} label="Endpoints" value={assessment.endpoint_count} />
        <Metric icon={<ShieldAlert className="h-4 w-4" />} label="No auth" value={assessment.unauthenticated_endpoint_count} />
        <Metric icon={<ShieldAlert className="h-4 w-4" />} label="High risk" value={assessment.high_risk_endpoint_count} />
      </div>
    </article>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background/60 p-3">
      <div className="flex items-center gap-2 text-muted-foreground">{icon}<span className="text-xs">{label}</span></div>
      <div className="mt-2 text-xl font-semibold">{value}</div>
    </div>
  );
}
