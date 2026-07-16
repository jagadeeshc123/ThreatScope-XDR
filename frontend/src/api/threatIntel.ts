import { apiClient } from './client';

export interface ThreatPage<T = Record<string, unknown>> { items: T[]; total: number; page: number; page_size: number }
export interface ThreatIndicator {
  id: number; indicator_type: string; value?: string; normalized_value?: string; display_value: string; title?: string;
  severity: string; confidence: number; tlp: string; active: boolean; revoked: boolean; false_positive: boolean;
  expired: boolean; tags: string[]; source_id?: number; created_at: string; updated_at: string;
  sightings?: Record<string, unknown>[]; matches?: Record<string, unknown>[]; watchlists?: Record<string, unknown>[];
  campaigns?: Record<string, unknown>[]; relationships?: Record<string, unknown>[];
}
export interface ThreatOverview { total_active_indicators: number; indicators_by_type: Record<string, number>; severity_distribution: Record<string, number>; confidence_distribution: Record<string, number>; active_watchlists: number; new_matches: number; high_risk_matches: number; module_distribution: Record<string, number>; recent_imports: Record<string, unknown>[]; recent_sightings: Record<string, unknown>[]; recent_escalations: Record<string, unknown>[] }

const body = <T>(request: Promise<{ data: T }>) => request.then(response => response.data);

export const threatIntelApi = {
  overview: () => body<ThreatOverview>(apiClient.get('/threat-intel/overview')),
  list: <T = Record<string, unknown>>(resource: string, params: Record<string, unknown> = {}) => body<ThreatPage<T>>(apiClient.get(`/threat-intel/${resource}`, { params })),
  get: <T = Record<string, unknown>>(resource: string, id: string | number) => body<T>(apiClient.get(`/threat-intel/${resource}/${id}`)),
  create: <T = Record<string, unknown>>(resource: string, payload: unknown) => body<T>(apiClient.post(`/threat-intel/${resource}`, payload)),
  update: <T = Record<string, unknown>>(resource: string, id: string | number, payload: unknown) => body<T>(apiClient.patch(`/threat-intel/${resource}/${id}`, payload)),
  remove: (path: string) => body<{ ok: boolean }>(apiClient.delete(`/threat-intel/${path}`)),
  importFile: (sourceId: number, file: File) => { const form = new FormData(); form.append('source_id', String(sourceId)); form.append('file', file); return body<Record<string, unknown>>(apiClient.post('/threat-intel/imports', form, { headers: { 'Content-Type': 'multipart/form-data' } })); },
  runCorrelation: (maximum_records = 1000) => body<Record<string, unknown>>(apiClient.post('/threat-intel/correlation/run', { maximum_records })),
  reviewMatch: (id: number, payload: { status: string; analyst_note?: string; case_id?: number }) => body<Record<string, unknown>>(apiClient.post(`/threat-intel/matches/${id}/review`, payload)),
  escalateMatch: (id: number, payload: { confirmed: boolean; case_id?: number; case_title?: string; analyst_note?: string }) => body<Record<string, unknown>>(apiClient.post(`/threat-intel/matches/${id}/escalate`, payload)),
};

