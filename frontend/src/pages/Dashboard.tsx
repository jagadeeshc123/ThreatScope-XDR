import { useState, useEffect } from 'react';
import { ShieldAlert, Crosshair, Search, Target as TargetIcon } from 'lucide-react';
import { apiClient } from '../api/client';
import type { DashboardSummary } from '../types';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const COLORS = {
  critical: '#e53e3e',
  high: '#dd6b20',
  medium: '#d69e2e',
  low: '#3182ce',
  info: '#718096',
};

export function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSummary = async () => {
      try {
        const res = await apiClient.get<DashboardSummary>('/dashboard/summary');
        setSummary(res.data);
      } catch (err) {
        console.error("Failed to fetch dashboard summary", err);
      } finally {
        setLoading(false);
      }
    };
    fetchSummary();
  }, []);

  if (loading || !summary) {
    return <div className="p-8 flex items-center justify-center h-full">Loading dashboard...</div>;
  }

  const chartData = Object.entries(summary.severity_distribution).map(([key, value]) => ({
    name: key.charAt(0).toUpperCase() + key.slice(1),
    value,
    color: COLORS[key as keyof typeof COLORS] || '#000',
  })).filter(d => d.value > 0);

  return (
    <div className="p-8 space-y-8">
      <h1 className="text-3xl font-bold tracking-tight">Dashboard Overview</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-card border border-border rounded-xl p-6 shadow-sm flex items-center">
          <div className="p-4 bg-primary/10 rounded-full mr-4 text-primary">
            <TargetIcon className="w-8 h-8" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground font-medium">Total Targets</p>
            <p className="text-3xl font-bold">{summary.total_targets}</p>
          </div>
        </div>
        <div className="bg-card border border-border rounded-xl p-6 shadow-sm flex items-center">
          <div className="p-4 bg-secondary/20 rounded-full mr-4 text-secondary-foreground">
            <Search className="w-8 h-8" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground font-medium">Total Scans</p>
            <p className="text-3xl font-bold">{summary.total_scans}</p>
          </div>
        </div>
        <div className="bg-card border border-border rounded-xl p-6 shadow-sm flex items-center">
          <div className="p-4 bg-destructive/10 rounded-full mr-4 text-destructive">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground font-medium">Total Findings</p>
            <p className="text-3xl font-bold">{summary.total_findings}</p>
          </div>
        </div>
        <div className="bg-card border border-border rounded-xl p-6 shadow-sm flex items-center">
          <div className="p-4 bg-accent/20 rounded-full mr-4 text-accent-foreground">
            <Crosshair className="w-8 h-8" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground font-medium">Active Scans</p>
            <p className="text-3xl font-bold">{summary.active_scans}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-card border border-border rounded-xl p-6 shadow-sm">
          <h2 className="text-xl font-bold mb-4">Severity Distribution</h2>
          <div className="h-64">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-muted-foreground">No findings yet</div>
            )}
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl p-6 shadow-sm">
          <h2 className="text-xl font-bold mb-4">Recent Scans</h2>
          <div className="space-y-4">
            {summary.recent_scans.length > 0 ? (
              summary.recent_scans.map(scan => (
                <div key={scan.id} className="flex justify-between items-center p-4 border border-border rounded-lg bg-background/50 hover:bg-background/80 transition-colors">
                  <div>
                    <p className="font-semibold text-sm">Scan #{scan.id} - {scan.profile}</p>
                    <p className="text-xs text-muted-foreground">{new Date(scan.started_at).toLocaleString()}</p>
                  </div>
                  <div className="text-right">
                    <span className={`inline-block px-2 py-1 rounded text-xs font-bold uppercase ${scan.status === 'completed' ? 'bg-primary/20 text-primary' : 'bg-muted text-muted-foreground'}`}>
                      {scan.status}
                    </span>
                    <p className="text-xs text-muted-foreground mt-1">Findings: {scan.total_findings}</p>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center text-muted-foreground py-8">No recent scans</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
