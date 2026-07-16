import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { threatIntelApi } from '../../api/threatIntel';
import { EmptyState, SectionCard } from '../../components/ui';

export function useThreatPage<T = Record<string, unknown>>(resource: string, params: Record<string, unknown> = {}) {
  const [data, setData] = useState<{ items: T[]; total: number; page: number; page_size: number } | null>(null);
  const [error, setError] = useState('');
  const key = JSON.stringify(params);
  const load = useCallback(() => threatIntelApi.list<T>(resource, params).then(setData).catch(() => setError(`Unable to load ${resource.replaceAll('-', ' ')}.`)), [resource, key]); // oxlint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { void load(); }, [load]);
  return { data, error, load };
}

export function ResourceTable({ title, items, columns, detailBase, empty = 'No records yet.' }: { title: string; items: Array<Record<string, unknown>>; columns: Array<[string, string, ((item: Record<string, unknown>) => ReactNode)?]>; detailBase?: string; empty?: string }) {
  return <SectionCard title={title}>{items.length ? <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>{columns.map(([key, label]) => <th key={key} className="border-b p-3 text-muted-foreground">{label}</th>)}{detailBase && <th className="border-b p-3">Action</th>}</tr></thead><tbody>{items.map(item => <tr key={String(item.id)} className="border-b border-border/50">{columns.map(([key,, render]) => <td key={key} className="p-3 align-top">{render ? render(item) : String(item[key] ?? '—')}</td>)}{detailBase && <td className="p-3"><Link className="text-primary hover:underline" to={`${detailBase}/${String(item.id)}`}>View</Link></td>}</tr>)}</tbody></table></div> : <EmptyState title="No records" description={empty} />}</SectionCard>;
}

export function FormField({ label, children }: { label: string; children: ReactNode }) { return <label className="grid gap-1 text-sm"><span className="text-muted-foreground">{label}</span>{children}</label>; }
export const inputClass = 'rounded border border-border bg-background px-3 py-2 text-sm';

