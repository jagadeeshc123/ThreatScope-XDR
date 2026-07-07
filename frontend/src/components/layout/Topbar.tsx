import { Bell, Search, User, Check, Settings, LogOut, Shield } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import type { Notification, UserProfile } from '../../types';
import { getNotifications, getProfile, getUnreadNotificationCount, markNotificationRead } from '../../data/demoData';

export function Topbar() {
  const [query, setQuery] = useState('');
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  
  const navigate = useNavigate();
  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchProfile();
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 10000); // Poll every 10s
    
    const handleClickOutside = (event: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setShowProfile(false);
      }
    };
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      clearInterval(interval);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const fetchProfile = async () => {
    setProfile(getProfile());
  };

  const fetchNotifications = async () => {
    setNotifications(getNotifications(5));
    setUnreadCount(getUnreadNotificationCount());
  };

  const handleSearch = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && query.trim()) {
      navigate(`/search?q=${encodeURIComponent(query.trim())}`);
    }
  };

  const markAsRead = async (id: number) => {
    try {
      markNotificationRead(id);
      fetchNotifications();
    } catch {}
  };

  return (
    <header className="relative z-50 flex h-16 shrink-0 items-center justify-between border-b border-border bg-card/95 px-4 backdrop-blur sm:px-6">
      <div className="flex min-w-0 flex-1 items-center gap-4">
        <div className="flex items-center gap-2 lg:hidden">
          <Shield className="h-5 w-5 text-primary" />
          <span className="font-semibold">VulnScope</span>
        </div>
        <div className="relative hidden w-full max-w-md md:block">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search targets, scans, or findings..."
            className="h-10 w-full rounded-md border border-input bg-background/70 pl-9 pr-4 text-sm text-foreground placeholder:text-muted-foreground/80"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleSearch}
          />
        </div>
      </div>
      
      <div className="flex items-center gap-2">
        {/* Notifications */}
        <div className="relative" ref={notifRef}>
          <button 
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative rounded-md p-2 transition-colors hover:bg-muted"
            aria-label="Notifications"
          >
            <Bell className="h-5 w-5 text-muted-foreground" />
            {unreadCount > 0 && (
              <span className="absolute right-1.5 top-1.5 h-2.5 w-2.5 rounded-full border-2 border-card bg-red-500"></span>
            )}
          </button>
          
          {showNotifications && (
            <div className="absolute right-0 z-50 mt-2 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-lg border border-border bg-card shadow-xl shadow-black/30">
              <div className="flex items-center justify-between border-b border-border bg-muted/30 p-3">
                <h3 className="text-sm font-semibold">Notifications</h3>
                <span className="text-xs text-muted-foreground">{unreadCount} unread</span>
              </div>
              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="p-4 text-center text-sm text-muted-foreground">No recent notifications</div>
                ) : (
                  notifications.map(n => (
                    <div key={n.id} className={`border-b border-border p-3 transition-colors hover:bg-muted/50 ${!n.is_read ? 'bg-primary/5' : ''}`}>
                      <div className="flex items-start justify-between gap-3">
                        <div className="text-sm font-medium">{n.title}</div>
                        {!n.is_read && (
                          <button onClick={() => markAsRead(n.id)} className="text-muted-foreground hover:text-primary">
                            <Check className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                      <div className="mt-1 text-xs leading-5 text-muted-foreground">{n.message}</div>
                    </div>
                  ))
                )}
              </div>
              <div className="border-t border-border bg-muted/30 p-2 text-center">
                <Link to="/notifications" onClick={() => setShowNotifications(false)} className="text-xs text-primary hover:underline font-medium">View all notifications</Link>
              </div>
            </div>
          )}
        </div>
        
        {/* Profile */}
        <div className="relative" ref={profileRef}>
          <button 
            onClick={() => setShowProfile(!showProfile)}
            className="flex h-9 w-9 items-center justify-center rounded-full border border-primary/30 bg-primary/15 text-sm font-semibold text-primary transition-colors hover:bg-primary/25"
            aria-label="Profile"
          >
            {profile ? profile.avatar_initials : <User className="w-4 h-4" />}
          </button>
          
          {showProfile && (
            <div className="absolute right-0 z-50 mt-2 w-60 overflow-hidden rounded-lg border border-border bg-card py-1 shadow-xl shadow-black/30">
              <div className="border-b border-border px-4 py-3">
                <p className="text-sm font-medium">{profile?.full_name || 'Loading...'}</p>
                <p className="text-xs text-muted-foreground truncate">{profile?.email}</p>
              </div>
              <Link to="/profile" onClick={() => setShowProfile(false)} className="flex items-center px-4 py-2 text-sm hover:bg-muted transition-colors">
                <User className="w-4 h-4 mr-2 text-muted-foreground" />
                View Profile
              </Link>
              <Link to="/settings" onClick={() => setShowProfile(false)} className="flex items-center px-4 py-2 text-sm hover:bg-muted transition-colors">
                <Settings className="w-4 h-4 mr-2 text-muted-foreground" />
                Settings
              </Link>
              <div className="border-t border-border my-1"></div>
              <button className="w-full flex items-center px-4 py-2 text-sm text-destructive hover:bg-destructive/10 transition-colors text-left">
                <LogOut className="w-4 h-4 mr-2" />
                End Demo Session
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
