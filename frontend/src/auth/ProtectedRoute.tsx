import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './useAuth';
import { permissionForPath } from './permissions';

export function ProtectedRoute() {
  const { user, loading, sessionExpired } = useAuth();
  const location = useLocation();
  if (loading) return <div className="grid min-h-screen place-items-center bg-background text-sm text-muted-foreground">Checking secure session...</div>;
  if (!user) {
    // Unmount protected content while the global guard owns the expiry flow.
    if (sessionExpired) return <div className="min-h-screen bg-background" aria-hidden="true" />;
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  if (user.must_change_password && location.pathname !== '/change-password') return <Navigate to="/change-password" replace />;
  const permission = permissionForPath(location.pathname);
  if (permission && !user.permissions.includes(permission)) return <Navigate to="/forbidden" replace />;
  return <Outlet />;
}
