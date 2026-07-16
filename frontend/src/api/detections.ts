import { apiClient } from './client';

export interface DetectionPage<T=Record<string, unknown>> { items:T[]; total:number; page:number; page_size:number }
export interface DetectionRule { id:number; title:string; description:string; rule_uuid:string; rule_format:string; lifecycle_status:string; severity:string; confidence:number; quality_score:number; current_version:number; enabled:boolean; system_owned:boolean; rule_content?:Record<string,unknown>; normalized_condition?:Record<string,unknown>; versions?:Record<string,unknown>[]; tests?:Record<string,unknown>[]; techniques?:Record<string,unknown>[]; validation?:Record<string,unknown> }
const body=<T>(request:Promise<{data:T}>)=>request.then(response=>response.data);
export const detectionsApi={
  overview:()=>body<Record<string,unknown>>(apiClient.get('/detections/overview')),
  raw:<T=Record<string,unknown>>(path:string)=>body<T>(apiClient.get(`/detections/${path}`)),
  list:<T=Record<string,unknown>>(resource:string,params:Record<string,unknown>={})=>body<DetectionPage<T>>(apiClient.get(`/detections/${resource}`,{params})),
  get:<T=Record<string,unknown>>(resource:string,id:string|number)=>body<T>(apiClient.get(`/detections/${resource}/${id}`)),
  create:<T=Record<string,unknown>>(resource:string,payload:unknown)=>body<T>(apiClient.post(`/detections/${resource}`,payload)),
  update:<T=Record<string,unknown>>(resource:string,id:string|number,payload:unknown)=>body<T>(apiClient.patch(`/detections/${resource}/${id}`,payload)),
  post:<T=Record<string,unknown>>(path:string,payload:unknown={})=>body<T>(apiClient.post(`/detections/${path}`,payload)),
  remove:(path:string)=>body<{ok:boolean}>(apiClient.delete(`/detections/${path}`)),
};
