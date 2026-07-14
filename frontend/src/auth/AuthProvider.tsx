import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { apiClient } from '../api/client';
import { clearCsrfToken, refreshCsrfToken } from './csrf';
import { AuthContext, type AuthUser } from './authContext';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);

  const reload = useCallback(async () => {
    try {
      const response = await apiClient.get<AuthUser>('/auth/me');
      setUser(response.data);
      await refreshCsrfToken();
    } catch {
      setUser(null);
      clearCsrfToken();
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void reload(); }, [reload]);
  useEffect(() => {
    const expired = () => { setUser(null); setSessionExpired(true); };
    window.addEventListener('threatscope:session-expired', expired);
    return () => window.removeEventListener('threatscope:session-expired', expired);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    setSessionExpired(false);
    const response = await apiClient.post<{ requires_mfa: boolean; challenge_token?: string; user?: AuthUser }>('/auth/login', { username, password });
    if (response.data.user) { setUser(response.data.user); await refreshCsrfToken(); }
    return response.data;
  }, []);

  const completeMfa = useCallback(async (challengeToken: string, code: string, recoveryCode: boolean) => {
    const response = await apiClient.post<{ user: AuthUser }>('/auth/mfa/verify-login', { challenge_token: challengeToken, code, recovery_code: recoveryCode });
    setUser(response.data.user);
    await refreshCsrfToken();
  }, []);

  const logout = useCallback(async () => {
    try { await apiClient.post('/auth/logout'); } finally { setUser(null); clearCsrfToken(); }
  }, []);

  const value = useMemo(() => ({ user, loading, sessionExpired, login, completeMfa, logout, reload, can: (permission: string) => !!user?.permissions.includes(permission) }), [user, loading, sessionExpired, login, completeMfa, logout, reload]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
