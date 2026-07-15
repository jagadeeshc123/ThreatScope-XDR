import { apiClient } from './client';

export interface MfaStatus {
  enabled: boolean;
  setup_incomplete: boolean;
  method: string | null;
  label: string | null;
  enrolled_at: string | null;
  last_used_at: string | null;
  recovery_codes_remaining: number;
  pending_expires_at: string | null;
  issuer: string;
  account_label: string;
}

export interface MfaEnrollmentSetup {
  device_id: number;
  manual_setup_key: string;
  provisioning_uri: string;
  issuer: string;
  account_label: string;
  expires_at: string;
  operation: 'started' | 'restarted' | 'resumed';
  warning: string;
}

export interface MfaRecoveryResponse {
  ok?: boolean;
  recovery_codes: string[];
  warning: string;
}

export const mfaApi = {
  async getStatus() {
    return (await apiClient.get<MfaStatus>('/auth/mfa/status')).data;
  },
  async startEnrollment(currentPassword: string, restart = false) {
    return (await apiClient.post<MfaEnrollmentSetup>('/auth/mfa/enroll', {
      current_password: currentPassword,
      label: 'Authenticator app',
      restart,
    })).data;
  },
  async confirmEnrollment(deviceId: number, code: string) {
    return (await apiClient.post<MfaRecoveryResponse>('/auth/mfa/confirm', {
      device_id: deviceId,
      code,
    })).data;
  },
  async cancelEnrollment() {
    return (await apiClient.post<{ ok: boolean; cancelled: boolean }>('/auth/mfa/cancel')).data;
  },
  async disable(currentPassword: string, code: string, recoveryCode: boolean) {
    return (await apiClient.post<{ ok: boolean; other_sessions_revoked: number }>('/auth/mfa/disable', {
      current_password: currentPassword,
      code,
      recovery_code: recoveryCode,
      confirm_disable: true,
    })).data;
  },
  async regenerateRecoveryCodes(currentPassword: string, code: string, recoveryCode: boolean) {
    return (await apiClient.post<MfaRecoveryResponse>('/auth/mfa/recovery/regenerate', {
      current_password: currentPassword,
      code,
      recovery_code: recoveryCode,
    })).data;
  },
};
