import { apiClient } from './client';

export type AnalyticsRecord = Record<string, unknown> & { id: number };
export interface Page<T = AnalyticsRecord> { items: T[]; page: number; page_size: number; total: number; pages: number }
export interface CatalogItem { key?: string; template_key?: string; display_name: string; description: string; source_domain?: string; available?: boolean; unavailable_reason?: string; allowed_detector_methods?: string[]; supported_window_sizes?: number[]; selected_feature_keys?: string[]; approved_method?: string; minimum_samples?: number }
export interface DetectorConfiguration { template_key: string; feature_keys: string[]; method: string; observation_window_seconds: number; baseline_lookback_seconds: number; minimum_historical_windows: number; seasonality: string; threshold_parameters: Record<string, unknown>; severity_mapping: Record<string, number>; confidence_rules: Record<string, unknown>; cooldown_seconds: number; deduplication_period_seconds: number; maximum_late_arrival_seconds: number; scoring_frequency_seconds: number; source_scope: 'platform'|'entity'|'approved_peer_group'; peer_group_key?: string; winsorize: boolean; ensemble: Record<string, unknown>[] }
export interface DetectorCreate { detector_key: string; name: string; description: string; configuration: DetectorConfiguration; reason: string; demo_owned?: boolean }

const get = async <T>(path: string, params?: Record<string, unknown>) => (await apiClient.get<T>(`/analytics/${path}`, { params })).data;
const post = async <T>(path: string, data: unknown) => (await apiClient.post<T>(`/analytics/${path}`, data)).data;
const patch = async <T>(path: string, data: unknown) => (await apiClient.patch<T>(`/analytics/${path}`, data)).data;

export const analyticsApi = {
  overview: () => get<Record<string, unknown>>('overview'),
  metrics: () => get<Record<string, unknown>>('metrics'),
  features: () => get<{items: CatalogItem[]}>('catalog/features'),
  templates: () => get<{items: CatalogItem[]}>('catalog/detectors'),
  methods: () => get<{items: Array<{key:string;display_name:string;description:string}>}>('catalog/methods'),
  list: <T=AnalyticsRecord>(resource: string, params: Record<string, unknown> = {}) => get<Page<T>>(resource, params),
  one: <T=AnalyticsRecord>(resource: string, id: string|number) => get<T>(`${resource}/${id}`),
  detector: (id: string|number) => get<AnalyticsRecord>(`detectors/${id}`),
  createDetector: (data: DetectorCreate) => post<AnalyticsRecord>('detectors', data),
  updateDetector: (id: string|number, data: unknown) => patch<AnalyticsRecord>(`detectors/${id}`, data),
  versions: (id: string|number) => get<{items:AnalyticsRecord[]}>(`detectors/${id}/versions`),
  createVersion: (id: string|number, data: unknown) => post<AnalyticsRecord>(`detectors/${id}/versions`, data),
  detectorAction: (id: string|number, action: string, data: unknown) => post<AnalyticsRecord>(`detectors/${id}/${action}`, data),
  buildBaseline: (data: unknown) => post<{items:AnalyticsRecord[]}>('baselines/build', data),
  runBacktest: (data: unknown) => post<AnalyticsRecord>('backtests', data),
  anomaly: (id: string|number) => get<AnalyticsRecord>(`anomalies/${id}`),
  explanation: (id: string|number) => get<Record<string, unknown>>(`anomalies/${id}/explanation`),
  anomalyAction: (id: string|number, action: string, data: unknown) => post<AnalyticsRecord>(`anomalies/${id}/${action}`, data),
  feedback: (id: string|number, data: unknown) => post<AnalyticsRecord>(`anomalies/${id}/feedback`, data),
  createSuppression: (data: unknown) => post<AnalyticsRecord>('suppressions', data),
  updateSuppression: (id: string|number, data: unknown) => patch<AnalyticsRecord>(`suppressions/${id}`, data),
  acknowledgeDrift: (id: string|number, data: unknown) => post<AnalyticsRecord>(`drift/${id}/acknowledge`, data),
  processDue: (batch_size = 25) => post<Record<string, unknown>>('process-due', {batch_size}),
  createReport: (data: unknown) => post<AnalyticsRecord>('reports', data),
  reportHtml: async (id: string|number) => (await apiClient.get<string>(`/analytics/reports/${id}/html`, { responseType: 'text' })).data,
  downloadReport: async (id: string|number) => (await apiClient.get<Blob>(`/analytics/reports/${id}/export`, {responseType:'blob'})).data,
};
