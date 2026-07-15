import type { ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { SessionExpiryModal } from '../pages/access/components/SessionExpiryModal';
import { useAuth } from './useAuth';

export function SessionExpiryGuard({ children }: { children: ReactNode }) {
  const { sessionExpired } = useAuth();
  const location = useLocation();
  const publicPath = ['/', '/login', '/signup', '/account-pending', '/account-rejected', '/known-limitations', '/mfa-challenge', '/forbidden'].includes(location.pathname);
  return <>{children}{sessionExpired && !publicPath && <SessionExpiryModal />}</>;
}
