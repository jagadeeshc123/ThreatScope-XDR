export function SourceModuleBadge({value}:{value:string}){return <span className="rounded bg-indigo-500/10 px-2 py-1 text-xs text-indigo-300">{value.replaceAll('_',' ')}</span>}
