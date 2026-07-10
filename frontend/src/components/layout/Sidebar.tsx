import { Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Target, Activity, FileText, Settings, Network } from 'lucide-react';
import clsx from 'clsx';

export function Sidebar() {
  const location = useLocation();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Targets', path: '/targets', icon: Target },
    { name: 'Scans', path: '/scans', icon: Activity },
    { name: 'API Security', path: '/api-security', icon: Network },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Policies', path: '/policies', icon: Shield },
  ];

  return (
    <aside className="hidden h-screen w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar lg:flex">
      <div className="flex h-16 items-center gap-3 border-b border-sidebar-border px-5">
        <div className="rounded-md bg-sidebar-primary/15 p-2 text-sidebar-primary">
          <Shield className="h-5 w-5" />
        </div>
        <div>
          <span className="block text-base font-semibold tracking-wide text-sidebar-foreground">VulnScope</span>
          <span className="block text-xs text-sidebar-foreground/55">Security assessment</span>
        </div>
      </div>
      <nav className="flex-1 space-y-1.5 px-3 py-5">
        {navItems.map((item) => {
          const isActive = location.pathname.startsWith(item.path);
          return (
            <Link
              key={item.name}
              to={item.path}
              className={clsx(
                "flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
                isActive 
                  ? "bg-sidebar-primary/12 text-sidebar-primary shadow-[inset_3px_0_0_hsl(var(--sidebar-primary))]" 
                  : "text-sidebar-foreground/72 hover:bg-sidebar-accent/70 hover:text-sidebar-accent-foreground"
              )}
            >
              <item.icon className="h-4 w-4" />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border p-3">
        <Link to="/settings" className={clsx("flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors", location.pathname === '/settings' ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')}>
          <Settings className="h-4 w-4" />
          <span>Settings</span>
        </Link>
      </div>
    </aside>
  );
}
