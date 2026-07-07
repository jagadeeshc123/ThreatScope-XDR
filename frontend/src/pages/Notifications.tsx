import { useState, useEffect } from 'react';
import type { Notification } from '../types';
import { Bell, Check, CheckCircle2, Trash2, Info, AlertTriangle, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';
import { deleteNotification as deleteDemoNotification, getNotifications, markAllNotificationsRead as markAllDemoNotificationsRead, markNotificationRead as markDemoNotificationRead } from '../data/demoData';

export function Notifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchNotifications();
  }, []);

  const fetchNotifications = async () => {
    setNotifications(getNotifications(100));
    setLoading(false);
  };

  const markAsRead = async (id: number) => {
    try {
      markDemoNotificationRead(id);
      setNotifications(notifications.map(n => n.id === id ? { ...n, is_read: true } : n));
    } catch {}
  };

  const markAllRead = async () => {
    try {
      markAllDemoNotificationsRead();
      setNotifications(notifications.map(n => ({ ...n, is_read: true })));
      toast.success('All notifications marked as read');
    } catch {
      toast.error('Failed to mark all as read');
    }
  };

  const deleteNotification = async (id: number) => {
    try {
      deleteDemoNotification(id);
      setNotifications(notifications.filter(n => n.id !== id));
      toast.success('Notification deleted');
    } catch {
      toast.error('Failed to delete notification');
    }
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
              <div key={n.id} className={`p-4 flex gap-4 items-start transition-colors ${!n.is_read ? 'bg-primary/5' : 'hover:bg-muted/50'}`}>
                <div className="shrink-0 mt-1">
                  {getIcon(n.type)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between items-start">
                    <h4 className={`text-base font-medium ${!n.is_read ? 'text-foreground' : 'text-muted-foreground'}`}>
                      {n.title}
                    </h4>
                    <span className="text-xs text-muted-foreground whitespace-nowrap ml-4">
                      {new Date(n.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className={`text-sm mt-1 ${!n.is_read ? 'text-muted-foreground' : 'text-muted-foreground/70'}`}>
                    {n.message}
                  </p>
                </div>
                <div className="shrink-0 flex space-x-2">
                  {!n.is_read && (
                    <button 
                      onClick={() => markAsRead(n.id)}
                      title="Mark as read"
                      className="p-1.5 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-md transition-colors"
                    >
                      <Check className="w-4 h-4" />
                    </button>
                  )}
                  <button 
                    onClick={() => deleteNotification(n.id)}
                    title="Delete"
                    className="p-1.5 text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-md transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
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
