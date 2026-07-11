import { Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Target, Activity, FileText, Settings, Network, Radar, ChevronDown, FileSearch } from 'lucide-react';
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
        <details className="group pt-1" open={location.pathname.startsWith('/soc')}>
          <summary className={clsx("flex cursor-pointer list-none items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium", location.pathname.startsWith('/soc') ? "bg-sidebar-primary/12 text-sidebar-primary" : "text-sidebar-foreground/72 hover:bg-sidebar-accent/70")}><Radar className="h-4 w-4"/><span className="flex-1">SOC Monitor</span><ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180"/></summary>
          <div className="ml-5 mt-1 space-y-0.5 border-l border-sidebar-border pl-2">
            {[['Overview','/soc'],['Sources','/soc/sources'],['Events','/soc/events'],['Alerts','/soc/alerts'],['Rules','/soc/rules'],['Simulator','/soc/simulator'],['Blocklist','/soc/blocklist'],['Reports','/soc/reports']].map(([name,path])=><Link key={path} to={path} className={clsx("block rounded px-3 py-1.5 text-xs", location.pathname===path||path!=='/soc'&&location.pathname.startsWith(`${path}/`) ? 'bg-primary/10 text-primary' : 'text-muted-foreground hover:text-foreground')}>{name}</Link>)}
          </div>
        </details>
        <details className="group pt-1" open={location.pathname.startsWith('/document-threats')}>
          <summary className={clsx("flex cursor-pointer list-none items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium", location.pathname.startsWith('/document-threats') ? "bg-sidebar-primary/12 text-sidebar-primary" : "text-sidebar-foreground/72 hover:bg-sidebar-accent/70")}><FileSearch className="h-4 w-4"/><span className="flex-1">Document Threats</span><ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180"/></summary>
          <div className="ml-5 mt-1 space-y-0.5 border-l border-sidebar-border pl-2">{[['Overview','/document-threats'],['Analyze PDF','/document-threats/analyze'],['Analyses','/document-threats/analyses'],['Reports','/document-threats/reports']].map(([name,path])=><Link key={path} to={path} className={clsx("block rounded px-3 py-1.5 text-xs",location.pathname===path||path!=='/document-threats'&&location.pathname.startsWith(`${path}/`)?'bg-primary/10 text-primary':'text-muted-foreground hover:text-foreground')}>{name}</Link>)}</div>
        </details>
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
