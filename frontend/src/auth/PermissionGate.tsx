import type { ReactNode } from 'react';
import { useAuth } from './useAuth';

export function PermissionGate({ permission, children, fallback = null }: { permission: string; children: ReactNode; fallback?: ReactNode }) {
  return useAuth().can(permission) ? children : fallback;
}
