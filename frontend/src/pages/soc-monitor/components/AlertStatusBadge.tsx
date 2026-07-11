import type { SocAlertStatus } from '../../../types';
export function AlertStatusBadge({ status }: { status: SocAlertStatus }) { return <span className="rounded-full border border-border px-2.5 py-1 text-xs font-medium capitalize">{status.replaceAll('_', ' ')}</span>; }
