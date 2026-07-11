import type { SocEventType } from '../../../types';
export function EventTypeBadge({ type }: { type: SocEventType }) { return <span className="rounded-md bg-primary/10 px-2 py-1 text-xs font-medium text-primary">{type.replaceAll('_', ' ')}</span>; }
