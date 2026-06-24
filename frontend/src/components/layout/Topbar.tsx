import { Bell, Search, User, Check, Settings, LogOut } from 'lucide-react';
import { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { apiClient } from '../../api/client';
import type { Notification, UserProfile } from '../../types';

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
    try {
      const res = await apiClient.get('/profile');
      setProfile(res.data);
    } catch (e) {}
  };

  const fetchNotifications = async () => {
    try {
      const res = await apiClient.get('/notifications?limit=5');
      setNotifications(res.data);
      const countRes = await apiClient.get('/notifications/unread-count');
      setUnreadCount(countRes.data.unread_count);
    } catch (e) {}
  };

  const handleSearch = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && query.trim()) {
      navigate(`/search?q=${encodeURIComponent(query.trim())}`);
    }
  };

  const markAsRead = async (id: number) => {
    try {
      await apiClient.patch(`/notifications/${id}/read`);
      fetchNotifications();
    } catch (e) {}
  };

  return (
    <header className="h-16 bg-card border-b border-border flex items-center justify-between px-6 shrink-0 relative z-50">
      <div className="flex items-center w-96">
        <div className="relative w-96 hidden md:block">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search targets, scans, or findings..."
            className="w-full bg-muted/50 border-none rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary placeholder:text-muted-foreground"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleSearch}
          />
        </div>
      </div>
      
      <div className="flex items-center space-x-4">
        {/* Notifications */}
        <div className="relative" ref={notifRef}>
          <button 
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2 hover:bg-muted rounded-full transition-colors relative"
          >
            <Bell className="w-5 h-5 text-muted-foreground" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2.5 h-2.5 bg-destructive rounded-full border-2 border-card"></span>
            )}
          </button>
          
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-card border border-border rounded-lg shadow-xl overflow-hidden z-50">
              <div className="p-3 border-b border-border flex justify-between items-center bg-muted/30">
                <h3 className="font-semibold text-sm">Notifications</h3>
                <span className="text-xs text-muted-foreground">{unreadCount} unread</span>
              </div>
              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="p-4 text-center text-sm text-muted-foreground">No recent notifications</div>
                ) : (
                  notifications.map(n => (
                    <div key={n.id} className={`p-3 border-b border-border hover:bg-muted/50 transition-colors ${!n.is_read ? 'bg-primary/5' : ''}`}>
                      <div className="flex justify-between items-start">
                        <div className="font-medium text-sm">{n.title}</div>
                        {!n.is_read && (
                          <button onClick={() => markAsRead(n.id)} className="text-muted-foreground hover:text-primary">
                            <Check className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">{n.message}</div>
                    </div>
                  ))
                )}
              </div>
              <div className="p-2 border-t border-border bg-muted/30 text-center">
                <Link to="/notifications" onClick={() => setShowNotifications(false)} className="text-xs text-primary hover:underline font-medium">View all notifications</Link>
              </div>
            </div>
          )}
        </div>
        
        {/* Profile */}
        <div className="relative" ref={profileRef}>
          <button 
            onClick={() => setShowProfile(!showProfile)}
            className="w-8 h-8 bg-primary/20 text-primary rounded-full flex items-center justify-center text-sm font-medium hover:bg-primary/30 transition-colors"
          >
            {profile ? profile.avatar_initials : <User className="w-4 h-4" />}
          </button>
          
          {showProfile && (
            <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-xl overflow-hidden z-50 py-1">
              <div className="px-4 py-3 border-b border-border">
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
