export function CaseStatusBadge({value}:{value:string}){return <span className="rounded bg-muted px-2 py-1 text-xs">{value.replaceAll('_',' ')}</span>}
