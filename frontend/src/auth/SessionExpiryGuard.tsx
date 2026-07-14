import type { ReactNode } from 'react';
import { SessionExpiryModal } from '../pages/access/components/SessionExpiryModal';
import { useAuth } from './useAuth';

export function SessionExpiryGuard({ children }: { children: ReactNode }) {
  const { sessionExpired } = useAuth();
  return <>{children}{sessionExpired && <SessionExpiryModal />}</>;
}
