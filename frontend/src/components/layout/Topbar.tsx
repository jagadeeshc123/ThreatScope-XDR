import { Bell, Check, LogOut, Search, Settings, Shield, User } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import type { Notification, UserProfile } from '../../types';
import { vulnscopeApi, VULNSCOPE_EVENTS } from '../../api/vulnscope';
import { useAuth } from '../../auth/useAuth';
import { apiClient } from '../../api/client';

export function Topbar() {
  const { user, logout } = useAuth();
  const [query, setQuery] = useState('');
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const [notificationsError, setNotificationsError] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  const fetchProfile = useCallback(async () => {
    try { setProfile(await vulnscopeApi.getProfile()); } catch { setProfile(null); }
  }, []);

  const fetchNotifications = useCallback(async () => {
    try {
      const [items, count] = await Promise.all([
        vulnscopeApi.listNotifications(5),
        vulnscopeApi.getUnreadNotificationCount(),
      ]);
      setNotifications(items);
      setUnreadCount(count.unread_count);
      setNotificationsError(false);
    } catch {
      setNotificationsError(true);
    }
  }, []);

  useEffect(() => {
    void fetchProfile();
    void fetchNotifications();
    const interval = window.setInterval(() => void fetchNotifications(), 10_000);
    const refreshProfile = () => void fetchProfile();
    const refreshNotifications = () => void fetchNotifications();
    const handleClickOutside = (event: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) setShowNotifications(false);
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) setShowProfile(false);
    };
    window.addEventListener(VULNSCOPE_EVENTS.profileUpdated, refreshProfile);
    window.addEventListener(VULNSCOPE_EVENTS.notificationsUpdated, refreshNotifications);
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener(VULNSCOPE_EVENTS.profileUpdated, refreshProfile);
      window.removeEventListener(VULNSCOPE_EVENTS.notificationsUpdated, refreshNotifications);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [fetchNotifications, fetchProfile]);

  useEffect(() => { if (user?.permissions.includes('operations:view')) void apiClient.get('/operations/demo/status').then(r => setDemoMode(Boolean(r.data.demo_mode))).catch(() => setDemoMode(false)); }, [user]);

  useEffect(() => {
    const currentQuery = new URLSearchParams(location.search).get('q') || '';
    if (location.pathname === '/search') setQuery(current => current === currentQuery ? current : currentQuery);
  }, [location.pathname, location.search]);

  useEffect(() => {
    const normalized = query.trim();
    const currentQuery = new URLSearchParams(location.search).get('q') || '';
    if (!normalized) {
      if (location.pathname === '/search' && currentQuery) navigate('/search', { replace: true });
      return;
    }
    const timer = window.setTimeout(() => {
      if (location.pathname !== '/search' || currentQuery !== normalized) navigate(`/search?q=${encodeURIComponent(normalized)}`);
    }, 400);
    return () => window.clearTimeout(timer);
  }, [location.pathname, location.search, navigate, query]);

  const handleSearch = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter' && query.trim()) navigate(`/search?q=${encodeURIComponent(query.trim())}`);
  };

  const markAsRead = async (id: number) => {
    try { await vulnscopeApi.markNotificationRead(id); } catch { setNotificationsError(true); }
  };

  const notificationPath = (notification: Notification) => {
    if (notification.entity_type === 'scan' && notification.entity_id) return `/scans?highlight=${notification.entity_id}`;
    if (notification.entity_type === 'report' && notification.entity_id) return `/reports?reportId=${notification.entity_id}`;
    if (notification.entity_type === 'target' && notification.entity_id) return `/targets?highlight=${notification.entity_id}`;
    if (notification.entity_type === 'soc_alert' && notification.entity_id) return `/soc/alerts/${notification.entity_id}`;
    if (notification.entity_type === 'soc_report' && notification.entity_id) return `/soc/reports/${notification.entity_id}`;
    if (notification.entity_type === 'soc_import') return '/soc/imports';
    if (notification.entity_type === 'soc_blocklist') return '/soc/blocklist';
    if (notification.entity_type === 'document_analysis' && notification.entity_id) return `/document-threats/analyses/${notification.entity_id}`;
    if (notification.entity_type === 'document_report' && notification.entity_id) return `/document-threats/reports/${notification.entity_id}`;
    if (notification.entity_type === 'phishing_analysis' && notification.entity_id) return `/phishing-defense/analyses/${notification.entity_id}`;
    if (notification.entity_type === 'phishing_report' && notification.entity_id) return `/phishing-defense/reports/${notification.entity_id}`;
    if (notification.entity_type === 'phishing_watchlist') return '/phishing-defense/watchlist';
    if (notification.entity_type === 'correlation_match' && notification.entity_id) return `/correlation/matches/${notification.entity_id}`;
    if (notification.entity_type === 'incident_case' && notification.entity_id) return `/correlation/cases/${notification.entity_id}`;
    if (notification.entity_type === 'incident_report' && notification.entity_id) return `/correlation/reports/${notification.entity_id}`;
    if (notification.entity_type === 'governance_risk' && notification.entity_id) return `/governance/risks/${notification.entity_id}`;
    if (notification.entity_type === 'governance_mapping') return '/governance/mappings';
    if (notification.entity_type === 'governance_exception') return '/governance/exceptions';
    if (notification.entity_type === 'governance_review' && notification.entity_id) return `/governance/reviews/${notification.entity_id}`;
    if (notification.entity_type === 'governance_report' && notification.entity_id) return `/governance/reports/${notification.entity_id}`;
    if (notification.entity_type === 'operational_backup' && notification.entity_id) return `/operations/backups/${notification.entity_id}`;
    if (notification.entity_type === 'operational_restore' && notification.entity_id) return `/operations/restores/${notification.entity_id}`;
    if (notification.entity_type === 'operational_export' && notification.entity_id) return `/operations/exports/${notification.entity_id}`;
    if (notification.entity_type === 'operational_release' && notification.entity_id) return `/operations/releases/${notification.entity_id}`;
    if (notification.entity_type === 'operational_job') return '/operations/jobs';
    return '/notifications';
  };

  return (
    <header className="relative z-50 flex h-16 shrink-0 items-center justify-between border-b border-border bg-card/95 px-4 backdrop-blur sm:px-6">
      <div className="flex min-w-0 flex-1 items-center gap-4">
        <div className="flex items-center gap-2 lg:hidden"><Shield className="h-5 w-5 text-primary" /><span className="font-semibold">VulnScope</span></div>
        <div className="relative hidden w-full max-w-md md:block">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input type="search" placeholder="Search targets, scans, findings, reports..." aria-label="Search VulnScope" className="h-10 w-full rounded-md border border-input bg-background/70 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground/80" value={query} onChange={event => setQuery(event.target.value)} onKeyDown={handleSearch} />
        </div>
      </div>

      <div className="flex items-center gap-2">
        {demoMode && <span className="hidden rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-1 text-xs text-amber-200 sm:inline">Demo Environment</span>}
        <div className="relative" ref={notifRef}>
          <button onClick={() => setShowNotifications(current => !current)} className="relative rounded-md p-2 transition-colors hover:bg-muted" aria-label={`Notifications${unreadCount ? `, ${unreadCount} unread` : ''}`}>
            <Bell className="h-5 w-5 text-muted-foreground" />
            {unreadCount > 0 && <span className="absolute right-0.5 top-0.5 flex min-h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">{unreadCount > 99 ? '99+' : unreadCount}</span>}
          </button>
          {showNotifications && (
            <div className="absolute right-0 z-50 mt-2 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-lg border border-border bg-card shadow-xl shadow-black/30">
              <div className="flex items-center justify-between border-b border-border bg-muted/30 p-3"><h3 className="text-sm font-semibold">Notifications</h3><span className="text-xs text-muted-foreground">{unreadCount} unread</span></div>
              <div className="max-h-80 overflow-y-auto">
                {notificationsError ? <div className="p-4 text-center text-sm text-destructive">Unable to load notifications.</div> : notifications.length === 0 ? <div className="p-4 text-center text-sm text-muted-foreground">No recent notifications</div> : notifications.map(notification => (
                  <Link key={notification.id} to={notificationPath(notification)} onClick={() => { setShowNotifications(false); if (!notification.is_read) void markAsRead(notification.id); }} className={`block border-b border-border p-3 transition-colors hover:bg-muted/50 ${!notification.is_read ? 'bg-primary/5' : ''}`}>
                    <div className="flex items-start justify-between gap-3"><div className="text-sm font-medium">{notification.title}</div>{!notification.is_read && <button type="button" aria-label="Mark as read" onClick={event => { event.preventDefault(); event.stopPropagation(); void markAsRead(notification.id); }} className="text-muted-foreground hover:text-primary"><Check className="h-3.5 w-3.5" /></button>}</div>
                    <div className="mt-1 text-xs leading-5 text-muted-foreground">{notification.message}</div>
                  </Link>
                ))}
              </div>
              <div className="border-t border-border bg-muted/30 p-2 text-center"><Link to="/notifications" onClick={() => setShowNotifications(false)} className="text-xs font-medium text-primary hover:underline">View all notifications</Link></div>
            </div>
          )}
        </div>

        <div className="relative" ref={profileRef}>
          <button onClick={() => setShowProfile(current => !current)} className="flex h-9 w-9 items-center justify-center rounded-full border border-primary/30 bg-primary/15 text-sm font-semibold text-primary transition-colors hover:bg-primary/25" aria-label="Profile">
            {user?.display_name?.split(/\s+/).map(part => part[0]).join('').slice(0, 2).toUpperCase() || <User className="h-4 w-4" />}
          </button>
          {showProfile && (
            <div className="absolute right-0 z-50 mt-2 w-60 overflow-hidden rounded-lg border border-border bg-card py-1 shadow-xl shadow-black/30">
              <div className="border-b border-border px-4 py-3"><p className="text-sm font-medium">{user?.display_name || profile?.full_name || 'Profile unavailable'}</p><p className="truncate text-xs text-muted-foreground">{user?.email || user?.username}</p></div>
              <Link to="/profile/security" onClick={() => setShowProfile(false)} className="flex items-center px-4 py-2 text-sm transition-colors hover:bg-muted"><User className="mr-2 h-4 w-4 text-muted-foreground" />Profile security</Link>
              <Link to="/profile/sessions" onClick={() => setShowProfile(false)} className="flex items-center px-4 py-2 text-sm transition-colors hover:bg-muted"><Shield className="mr-2 h-4 w-4 text-muted-foreground" />Active sessions</Link>
              {user?.permissions.includes('system:manage') && <Link to="/settings" onClick={() => setShowProfile(false)} className="flex items-center px-4 py-2 text-sm transition-colors hover:bg-muted"><Settings className="mr-2 h-4 w-4 text-muted-foreground" />Settings</Link>}
              <div className="my-1 border-t border-border" />
              <button onClick={() => void logout().then(() => navigate('/login', { replace: true }))} className="flex w-full items-center px-4 py-2 text-left text-sm text-red-200 hover:bg-muted"><LogOut className="mr-2 h-4 w-4" />Sign out</button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
