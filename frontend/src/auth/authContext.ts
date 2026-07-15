import { createContext } from 'react';

export interface AuthUser {
  id: number;
  username: string;
  display_name: string;
  email: string | null;
  status: string;
  is_system_admin: boolean;
  must_change_password: boolean;
  mfa_enabled: boolean;
  roles: string[];
  permissions: string[];
  last_login_at?: string | null;
  password_changed_at?: string | null;
}

export interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  sessionExpired: boolean;
  clearExpiredSession: () => void;
  login: (identifier: string, password: string) => Promise<import('../api/access').LoginResult>;
  completeMfa: (challengeToken: string, code: string, recoveryCode: boolean) => Promise<void>;
  logout: () => Promise<void>;
  reload: () => Promise<void>;
  can: (permission: string) => boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
