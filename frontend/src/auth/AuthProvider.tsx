import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { apiClient, registerUnauthorizedHandler } from '../api/client';
import { clearCsrfToken, refreshCsrfToken } from './csrf';
import { AuthContext, type AuthUser } from './authContext';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);
  const hasEstablishedSession = useRef(false);
  const sessionExpiryTriggered = useRef(false);
  const clearExpiredSession = useCallback(() => {
    hasEstablishedSession.current = false;
    sessionExpiryTriggered.current = false;
    setUser(null);
    setSessionExpired(false);
    clearCsrfToken();
  }, []);

  const reload = useCallback(async () => {
    try {
      const response = await apiClient.get<AuthUser>('/auth/me');
      setUser(response.data);
      hasEstablishedSession.current = true;
      sessionExpiryTriggered.current = false;
      setSessionExpired(false);
      await refreshCsrfToken();
    } catch {
      setUser(null);
      clearCsrfToken();
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void reload(); }, [reload]);
  useEffect(() => {
    registerUnauthorizedHandler(() => {
      if (!hasEstablishedSession.current || sessionExpiryTriggered.current) return;
      sessionExpiryTriggered.current = true;
      hasEstablishedSession.current = false;
      setUser(null);
      setSessionExpired(true);
    });
    return () => registerUnauthorizedHandler(null);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    hasEstablishedSession.current = false;
    setSessionExpired(false);
    sessionExpiryTriggered.current = false;
    const response = await apiClient.post<{ requires_mfa: boolean; challenge_token?: string; user?: AuthUser }>('/auth/login', { username, password });
    if (response.data.user) {
      hasEstablishedSession.current = true;
      setUser(response.data.user);
      await refreshCsrfToken();
    }
    return response.data;
  }, []);

  const completeMfa = useCallback(async (challengeToken: string, code: string, recoveryCode: boolean) => {
    const response = await apiClient.post<{ user: AuthUser }>('/auth/mfa/verify-login', { challenge_token: challengeToken, code, recovery_code: recoveryCode });
    hasEstablishedSession.current = true;
    sessionExpiryTriggered.current = false;
    setSessionExpired(false);
    setUser(response.data.user);
    await refreshCsrfToken();
  }, []);

  const logout = useCallback(async () => {
    hasEstablishedSession.current = false;
    sessionExpiryTriggered.current = false;
    setSessionExpired(false);
    try { await apiClient.post('/auth/logout'); } finally { setUser(null); clearCsrfToken(); }
  }, []);

  const value = useMemo(() => ({ user, loading, sessionExpired, clearExpiredSession, login, completeMfa, logout, reload, can: (permission: string) => !!user?.permissions.includes(permission) }), [user, loading, sessionExpired, clearExpiredSession, login, completeMfa, logout, reload]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
