import { useState, useEffect } from 'react';
import type { Notification } from '../types';
import { Bell, Check, CheckCircle2, Trash2, Info, AlertTriangle, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { vulnscopeApi, VULNSCOPE_EVENTS } from '../api/vulnscope';

export function Notifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    void fetchNotifications();
    const refresh = () => void fetchNotifications();
    window.addEventListener(VULNSCOPE_EVENTS.notificationsUpdated, refresh);
    return () => window.removeEventListener(VULNSCOPE_EVENTS.notificationsUpdated, refresh);
  }, []);

  const fetchNotifications = async () => {
    setLoading(true);
    setError(null);
    try {
      setNotifications(await vulnscopeApi.listNotifications(100));
    } catch {
      setError('Notifications could not be loaded from the backend.');
    } finally {
      setLoading(false);
    }
  };

  const markAsRead = async (id: number) => {
    try {
      await vulnscopeApi.markNotificationRead(id);
      setNotifications(current => current.map(n => n.id === id ? { ...n, is_read: true } : n));
    } catch { toast.error('Failed to mark notification as read'); }
  };

  const markAllRead = async () => {
    try {
      await vulnscopeApi.markAllNotificationsRead();
      setNotifications(current => current.map(n => ({ ...n, is_read: true })));
      toast.success('All notifications marked as read');
    } catch {
      toast.error('Failed to mark all as read');
    }
  };

  const deleteNotification = async (id: number) => {
    if (!confirm('Delete this notification?')) return;
    try {
      await vulnscopeApi.deleteNotification(id);
      setNotifications(current => current.filter(n => n.id !== id));
      toast.success('Notification deleted');
    } catch {
      toast.error('Failed to delete notification');
    }
  };

  const openNotification = async (notification: Notification) => {
    if (!notification.is_read) await markAsRead(notification.id);
    if (notification.entity_type === 'scan' && notification.entity_id) navigate(`/scans?highlight=${notification.entity_id}`);
    if (notification.entity_type === 'report' && notification.entity_id) navigate(`/reports?reportId=${notification.entity_id}`);
    if (notification.entity_type === 'target' && notification.entity_id) navigate(`/targets?highlight=${notification.entity_id}`);
    if (notification.entity_type === 'soc_alert' && notification.entity_id) navigate(`/soc/alerts/${notification.entity_id}`);
    if (notification.entity_type === 'soc_report' && notification.entity_id) navigate(`/soc/reports/${notification.entity_id}`);
    if (notification.entity_type === 'soc_import') navigate('/soc/imports');
    if (notification.entity_type === 'soc_blocklist') navigate('/soc/blocklist');
    if (notification.entity_type === 'document_analysis' && notification.entity_id) navigate(`/document-threats/analyses/${notification.entity_id}`);
    if (notification.entity_type === 'document_report' && notification.entity_id) navigate(`/document-threats/reports/${notification.entity_id}`);
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'success': return <CheckCircle2 className="w-5 h-5 text-green-500" />;
      case 'warning': return <AlertTriangle className="w-5 h-5 text-warning" />;
      case 'danger': return <ShieldAlert className="w-5 h-5 text-destructive" />;
      default: return <Info className="w-5 h-5 text-blue-500" />;
    }
  };

  if (loading) return <div className="p-6">Loading notifications...</div>;
  if (error) return <div className="mx-auto max-w-4xl p-8 text-center"><h1 className="text-xl font-semibold">Notifications unavailable</h1><p className="mt-2 text-sm text-muted-foreground">{error}</p><button onClick={() => void fetchNotifications()} className="mt-4 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Try Again</button></div>;

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Notifications</h1>
          <p className="text-muted-foreground mt-2">View and manage your alerts and system messages.</p>
        </div>
        {notifications.some(n => !n.is_read) && (
          <button 
            onClick={markAllRead}
            className="text-primary hover:bg-primary/10 px-4 py-2 rounded-md text-sm font-medium transition-colors"
          >
            Mark all as read
          </button>
        )}
      </div>

      <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
        {notifications.length === 0 ? (
          <div className="py-16 flex flex-col items-center justify-center text-center">
            <Bell className="w-12 h-12 text-muted-foreground/30 mb-4" />
            <h3 className="text-lg font-medium">No notifications yet</h3>
            <p className="text-muted-foreground mt-1">When scans complete or issues arise, they will appear here.</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {notifications.map(n => (
              <div key={n.id} className={`flex items-start gap-2 p-2 transition-colors ${!n.is_read ? 'bg-primary/5' : 'hover:bg-muted/50'}`}>
                <button
                  type="button"
                  onClick={() => void openNotification(n)}
                  className="flex min-w-0 flex-1 items-start gap-4 rounded-md p-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  aria-label={`Open notification: ${n.title}`}
                >
                  <span className="mt-1 shrink-0" aria-hidden="true">
                    {getIcon(n.type)}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-start justify-between">
                      <span className={`text-base font-medium ${!n.is_read ? 'text-foreground' : 'text-muted-foreground'}`}>
                        {n.title}
                      </span>
                      <time className="ml-4 whitespace-nowrap text-xs text-muted-foreground" dateTime={n.created_at}>
                        {new Date(n.created_at).toLocaleString()}
                      </time>
                    </span>
                    <span className={`mt-1 block text-sm ${!n.is_read ? 'text-muted-foreground' : 'text-muted-foreground/70'}`}>
                      {n.message}
                    </span>
                  </span>
                </button>
                <div className="flex shrink-0 space-x-2 pt-2">
                  {!n.is_read && (
                    <button
                      type="button"
                      onClick={() => void markAsRead(n.id)}
                      title="Mark as read"
                      aria-label={`Mark ${n.title} as read`}
                      className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary"
                    >
                      <Check className="h-4 w-4" aria-hidden="true" />
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => void deleteNotification(n.id)}
                    title="Delete"
                    aria-label={`Delete notification: ${n.title}`}
                    className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" aria-hidden="true" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
