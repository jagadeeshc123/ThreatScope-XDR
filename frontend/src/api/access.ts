import { apiClient } from './client';

export interface AuthProviderConfig { local_login_enabled:boolean; self_registration_enabled:boolean; registration_mode:'disabled'|'approval_required'|'auto_activate_limited'; approval_required:boolean; password_policy_summary:{minimum_length:number;maximum_length:number;common_passwords_rejected:boolean;identifier_inclusion_rejected:boolean}; privacy_notice_version:string }
export interface SafeAccount { username:string; display_name:string; email:string|null; rejection_reason?:string|null }
export interface LoginResult { requires_mfa:boolean; challenge_token?:string; user?:import('../auth/authContext').AuthUser; account_status?:string; next_route?:string; account?:SafeAccount }
export interface RegistrationPayload { email:string; username?:string; display_name:string; password:string; password_confirmation:string; terms_accepted:boolean; privacy_notice_version:string }
export interface RegistrationResult { registration_status:string; username:string; display_name:string; email:string; email_verified:false; approval_required:boolean; next_route:string }
export interface RegistrationRecord { id:number; username:string; display_name:string; email:string|null; safe_email:string|null; status:string; registration_source:string; roles:string[]; created_at:string; approved_at:string|null; rejected_at:string|null; rejection_reason?:string|null; email_verified:boolean }

export const accessApi = {
  providers: async () => (await apiClient.get<AuthProviderConfig>('/auth/providers')).data,
  register: async (payload:RegistrationPayload) => (await apiClient.post<RegistrationResult>('/auth/register',payload)).data,
  registrations: async (status?:string) => (await apiClient.get<{items:RegistrationRecord[];total:number}>('/admin/registrations',{params:{status:status||undefined}})).data,
  registration: async (id:number) => (await apiClient.get<RegistrationRecord>(`/admin/registrations/${id}`)).data,
  approve: async (id:number,roleKeys:string[],confirmAdministrator=false) => (await apiClient.post<RegistrationRecord>(`/admin/registrations/${id}/approve`,{role_keys:roleKeys,confirm_administrator:confirmAdministrator})).data,
  reject: async (id:number,reason:string) => (await apiClient.post<RegistrationRecord>(`/admin/registrations/${id}/reject`,{reason})).data,
  reopen: async (id:number) => (await apiClient.post<RegistrationRecord>(`/admin/registrations/${id}/reopen`)).data,
};
