export function EntityTypeBadge({value}:{value:string}){return <span className="rounded bg-cyan-500/10 px-2 py-1 text-xs text-cyan-300">{value.replaceAll('_',' ')}</span>}
