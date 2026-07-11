import type { SocConfidence } from '../../../types';
export function ConfidenceBadge({ confidence }: { confidence: SocConfidence }) { return <span className="text-xs font-medium uppercase text-muted-foreground">{confidence} confidence</span>; }
