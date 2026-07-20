const API_URL = import.meta.env.VITE_API_URL || '';
let csrfToken: string | null = null;
let refreshPromise: Promise<string> | null = null;

export const getCsrfToken = () => csrfToken;
export const clearCsrfToken = () => { csrfToken = null; };

export async function refreshCsrfToken(): Promise<string> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = fetch(`${API_URL}/api/auth/csrf`, { credentials: 'include', headers: { Accept: 'application/json' } })
    .then(async response => {
      if (!response.ok) throw new Error('CSRF token unavailable');
      const body = await response.json() as { csrf_token: string };
      csrfToken = body.csrf_token;
      return csrfToken;
    })
    .finally(() => { refreshPromise = null; });
  return refreshPromise;
}
