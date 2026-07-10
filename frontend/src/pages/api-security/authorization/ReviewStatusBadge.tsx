export function ReviewStatusBadge({ status }: { status: string }) {
  const tone = status === 'reviewed' || status === 'accepted' || status === 'resolved' ? 'text-emerald-200' : status === 'rejected' ? 'text-red-200' : 'text-amber-100';
  return <span className={`text-xs font-semibold capitalize ${tone}`}>{status.replaceAll('_', ' ')}</span>;
}
