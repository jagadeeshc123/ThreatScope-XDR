import { Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Target, Activity, FileText, Settings } from 'lucide-react';
import clsx from 'clsx';

export function Sidebar() {
  const location = useLocation();

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Targets', path: '/targets', icon: Target },
    { name: 'Scans', path: '/scans', icon: Activity },
    { name: 'Reports', path: '/reports', icon: FileText },
  ];

  return (
    <div className="w-64 bg-sidebar flex flex-col border-r border-sidebar-border h-full">
      <div className="h-16 flex items-center px-6 border-b border-sidebar-border">
        <Shield className="w-8 h-8 text-sidebar-primary mr-3" />
        <span className="text-sidebar-foreground font-bold text-xl tracking-wider">VulnScope</span>
      </div>
      <nav className="flex-1 px-4 py-6 space-y-2">
        {navItems.map((item) => {
          const isActive = location.pathname.startsWith(item.path);
          return (
            <Link
              key={item.name}
              to={item.path}
              className={clsx(
                "flex items-center px-4 py-3 rounded-md transition-colors",
                isActive 
                  ? "bg-sidebar-primary/10 text-sidebar-primary" 
                  : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              )}
            >
              <item.icon className="w-5 h-5 mr-3" />
              <span className="font-medium">{item.name}</span>
            </Link>
          );
        })}
      </nav>
      <div className="p-4 border-t border-border">
        <Link to="/settings" className={`flex items-center space-x-3 p-3 rounded-md transition-colors ${location.pathname === '/settings' ? 'bg-primary text-primary-foreground font-medium' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}`}>
          <Settings className="w-5 h-5" />
          <span>Settings</span>
        </Link>
      </div>
    </div>
  );
}
