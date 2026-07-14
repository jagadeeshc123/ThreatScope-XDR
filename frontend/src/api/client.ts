import axios from 'axios';
import { clearCsrfToken, getCsrfToken, refreshCsrfToken } from '../auth/csrf';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const apiClient = axios.create({
  baseURL: API_URL + '/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(async config => {
  const method = (config.method || 'get').toUpperCase();
  const mutation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
  const authExempt = config.url === '/auth/login' || config.url === '/auth/mfa/verify-login';
  if (mutation && !authExempt) {
    const token = getCsrfToken() || await refreshCsrfToken();
    config.headers.set('X-CSRF-Token', token);
  }
  return config;
});

apiClient.interceptors.response.use(response => response, async error => {
  const config = error.config as (typeof error.config & { _csrfRetried?: boolean }) | undefined;
  const detail = error.response?.data?.detail;
  if (error.response?.status === 403 && detail === 'CSRF validation failed' && config && !config._csrfRetried) {
    config._csrfRetried = true;
    const token = await refreshCsrfToken();
    config.headers.set('X-CSRF-Token', token);
    return apiClient.request(config);
  }
  if (error.response?.status === 401) {
    clearCsrfToken();
    window.dispatchEvent(new CustomEvent('threatscope:session-expired'));
  }
  return Promise.reject(error);
});
