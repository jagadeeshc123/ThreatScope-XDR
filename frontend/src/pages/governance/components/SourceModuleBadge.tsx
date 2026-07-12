export function SourceModuleBadge({value}:{value:string}){return <span className="rounded bg-muted px-2 py-1 text-xs font-medium">{value.replaceAll('_',' ')}</span>}
