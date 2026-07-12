export function ControlCoverageBadge({value}:{value:string}){return <span className="rounded-full border border-border bg-muted px-2 py-1 text-xs capitalize">{value.replaceAll('_',' ')}</span>}
