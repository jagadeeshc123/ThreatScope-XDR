export function HeaderSummaryCard({value}:{value:Record<string,unknown>}){return <pre className="overflow-auto whitespace-pre-wrap rounded bg-muted p-4 text-xs">{JSON.stringify(value,null,2)}</pre>}
