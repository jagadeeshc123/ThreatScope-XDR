import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowLeft, WandSparkles } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { toast } from 'sonner';
import type { ApiEndpoint, AuthorizationReview } from '../../../types';
import { vulnscopeApi } from '../../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard, SeverityBadge } from '../../../components/ui';
import { ManualValidationChecklist } from './ManualValidationChecklist';
import { ReviewStatusBadge } from './ReviewStatusBadge';

export function AuthorizationReviews() {
  const assessmentId = Number(useParams().assessmentId);
  const [reviews, setReviews] = useState<AuthorizationReview[]>([]);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [type, setType] = useState('');
  const [status, setStatus] = useState('');
  const load = useCallback(async () => { const [reviewRows, endpointRows] = await Promise.all([vulnscopeApi.listAuthorizationReviews(assessmentId), vulnscopeApi.listApiEndpoints(assessmentId)]); setReviews(reviewRows); setEndpoints(endpointRows); }, [assessmentId]);
  useEffect(() => { void load().catch(() => toast.error('Authorization reviews could not be loaded.')); }, [load]);
  const filtered = useMemo(() => reviews.filter(review => (!type || review.review_type === type) && (!status || review.analyst_decision === status)), [reviews, status, type]);
  const generate = async () => { const result = await vulnscopeApi.generateAuthorizationReview(assessmentId); toast.success(`${result.reviews_created} new review items generated.`); await load(); };
  const update = async (review: AuthorizationReview, decision: AuthorizationReview['analyst_decision']) => { await vulnscopeApi.updateAuthorizationReview(review.id, { analyst_decision: decision }); await load(); toast.success('Review decision saved.'); };

  return <PageShell><PageHeader title="Authorization Reviews" subtitle="Potential API1, API3, and API5 indicators from imported metadata. Manual validation remains explicit." actions={<><Link to={`/api-security/assessments/${assessmentId}`} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold"><ArrowLeft className="h-4 w-4" />Assessment</Link><button onClick={() => void generate()} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white"><WandSparkles className="h-4 w-4" />Generate reviews</button></>} />
    <SectionCard><div className="mb-4 flex flex-wrap gap-3"><select value={type} onChange={event => setType(event.target.value)} className="rounded-md border border-border bg-background px-3 py-2 text-sm"><option value="">All review types</option>{['object_level', 'function_level', 'property_level'].map(item => <option key={item}>{item.replaceAll('_', ' ')}</option>)}</select><select value={status} onChange={event => setStatus(event.target.value)} className="rounded-md border border-border bg-background px-3 py-2 text-sm"><option value="">All decisions</option>{['open', 'needs_testing', 'accepted', 'rejected'].map(item => <option key={item}>{item.replaceAll('_', ' ')}</option>)}</select></div>
      {!filtered.length ? <EmptyState title="No authorization reviews" description="Generate reviews after importing endpoint metadata." /> : <div className="space-y-4">{filtered.map(review => { const endpoint = endpoints.find(item => item.id === review.endpoint_id); return <article key={review.id} className="rounded-md border border-border bg-background/50 p-4"><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={review.severity} /><span className="text-xs font-semibold capitalize text-indigo-200">{review.review_type.replaceAll('_', ' ')}</span><ReviewStatusBadge status={review.analyst_decision} /><span className="text-xs text-muted-foreground">{review.confidence} confidence</span></div><h3 className="mt-3 font-mono text-sm">{endpoint ? `${endpoint.method} ${endpoint.path}` : `Endpoint #${review.endpoint_id}`}</h3><p className="mt-3 text-sm leading-6 text-muted-foreground">{review.risk_indicator}</p><p className="mt-2 text-sm"><strong>Expected:</strong> <span className="text-muted-foreground">{review.expected_behavior}</span></p><details className="mt-3"><summary className="cursor-pointer text-sm font-semibold text-indigo-200">Manual validation checklist</summary><div className="mt-3"><ManualValidationChecklist items={review.validation_checklist} /></div></details><div className="mt-4 flex flex-wrap gap-2"><select value={review.analyst_decision} onChange={event => void update(review, event.target.value as AuthorizationReview['analyst_decision'])} className="rounded-md border border-border bg-background px-3 py-2 text-sm">{['open', 'needs_testing', 'accepted', 'rejected'].map(item => <option key={item}>{item.replaceAll('_', ' ')}</option>)}</select></div></article>; })}</div>}
    </SectionCard></PageShell>;
}
