import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  FileText,
  Radar,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
} from 'lucide-react';
import { Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from 'recharts';
import type { DashboardSummary, Finding, Report, Scan, Target as TargetRecord } from '../types';
import { vulnscopeApi, type PolicyPack } from '../api/vulnscope';
import { EmptyState, FindingCard, PageHeader, PageShell, RiskScoreBadge, SectionCard, SeverityBadge, StatCard, StatusBadge } from '../components/ui';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#60a5fa',
  info: '#94a3b8',
};

export function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [targets, setTargets] = useState<TargetRecord[]>([]);
  const [policies, setPolicies] = useState<PolicyPack[]>([]);
  const [recentFindings, setRecentFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadDashboard = async () => {
      setLoading(true);
      setError(null);
      try {
        const [apiSummary, apiScans, apiReports, apiTargets, apiPolicies] = await Promise.all([
          vulnscopeApi.getDashboardSummary(),
          vulnscopeApi.listScans(),
          vulnscopeApi.listReports(),
          vulnscopeApi.listTargets(),
          vulnscopeApi.listPolicies(),
        ]);
        const findingGroups = await Promise.all(
          apiScans.slice(0, 5).map(scan => vulnscopeApi.listFindings(scan.id).catch(() => [])),
        );
        setSummary(apiSummary);
        setScans(apiScans);
        setReports(apiReports);
        setTargets(apiTargets);
        setPolicies(apiPolicies);
        setRecentFindings(findingGroups.flat().sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 4));
      } catch {
        setError('Dashboard data could not be loaded from the backend.');
      } finally {
        setLoading(false);
      }
    };

    void loadDashboard();
  }, []);

  if (loading) {
    return <PageShell><div className="text-muted-foreground">Loading dashboard...</div></PageShell>;
  }
  if (error || !summary) return <PageShell><EmptyState title="Dashboard unavailable" description={error || 'No dashboard summary was returned.'} /></PageShell>;

  const severityData = Object.entries(summary.severity_distribution)
    .map(([name, value]) => ({ name, value, color: SEVERITY_COLORS[name] || SEVERITY_COLORS.info }))
    .filter(item => item.value > 0);

  const completedScans = scans.filter(scan => scan.status === 'completed');
  const trendData = completedScans.slice(0, 7).reverse().map(scan => ({
    label: `#${scan.id}`,
    posture: scan.overall_posture_score,
    risk: Number(scan.risk_score.toFixed(1)),
  }));

  const highPriority = summary.critical_findings + summary.high_findings;
  const policyCheckCount = policies.reduce((total, policy) => total + policy.checks.length, 0);

  return (
    <PageShell>
      <PageHeader
        title="Dashboard Overview"
        subtitle="Monitor backend Web Exposure data, safe scan history, report coverage, and policy posture from one operational view."
        actions={
          <>
            <Link to="/scans/new" className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90">
              Start Scan <ArrowRight className="h-4 w-4" />
            </Link>
            <Link to="/reports" className="inline-flex h-10 items-center gap-2 rounded-md border border-border bg-card px-4 text-sm font-semibold text-foreground transition-colors hover:bg-muted">
              View Reports <FileText className="h-4 w-4" />
            </Link>
          </>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <StatCard label="Targets" value={summary.total_targets} detail="Authorized assets" icon={<Target className="h-5 w-5" />} tone="info" />
        <StatCard label="Scans" value={summary.total_scans} detail={`${summary.active_scans} active`} icon={<Search className="h-5 w-5" />} tone="good" />
        <StatCard label="Findings" value={summary.total_findings} detail="Observed issues" icon={<ShieldAlert className="h-5 w-5" />} tone="warn" />
        <StatCard label="Critical / High" value={highPriority} detail="Priority queue" icon={<AlertTriangle className="h-5 w-5" />} tone="danger" />
        <StatCard label="Reports" value={reports.length} detail="Generated outputs" icon={<FileText className="h-5 w-5" />} tone="default" />
        <StatCard label="Posture Score" value={completedScans.length > 0 ? <>{summary.overall_posture_score}<span className="text-base text-muted-foreground">/100</span></> : 'N/A'} detail="Completed scans only" icon={<Shield className="h-5 w-5" />} tone="good" />
      </div>

      <div className="grid gap-6 xl:grid-cols-5">
        <SectionCard className="xl:col-span-3" title="Scan Trend" subtitle="Risk and posture movement across recent scan records." icon={<Radar className="h-5 w-5" />}>
          <div className="h-72">
            {trendData.length > 1 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData} margin={{ top: 8, right: 18, left: -12, bottom: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="label" stroke="hsl(var(--muted-foreground))" tick={{ fontSize: 12 }} />
                  <YAxis stroke="hsl(var(--muted-foreground))" tick={{ fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }} />
                  <Line type="monotone" dataKey="posture" name="Posture" stroke="hsl(var(--primary))" strokeWidth={3} dot={{ r: 4 }} />
                  <Line type="monotone" dataKey="risk" name="Risk" stroke="#fb7185" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No scan trend yet" description="Run at least two scans to build a trend line." />
            )}
          </div>
        </SectionCard>

        <SectionCard className="xl:col-span-2" title="Severity Distribution" subtitle="Open findings grouped by severity." icon={<ShieldAlert className="h-5 w-5" />}>
          <div className="grid gap-4 lg:grid-cols-[1fr_150px]">
            <div className="h-72">
              {severityData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} cx="50%" cy="50%" innerRadius={58} outerRadius={86} paddingAngle={3} dataKey="value">
                      {severityData.map(entry => <Cell key={entry.name} fill={entry.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }} />
                    <Legend formatter={(value) => <span className="text-sm text-muted-foreground capitalize">{value}</span>} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState title="No findings yet" description="Completed scans with findings will appear here." />
              )}
            </div>
            <div className="space-y-2">
              {severityData.map(item => (
                <div key={item.name} className="flex items-center justify-between rounded-md border border-border bg-background/60 px-3 py-2">
                  <SeverityBadge severity={item.name} />
                  <span className="text-sm font-semibold">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <SectionCard className="xl:col-span-2" title="Recent Scans" subtitle="Latest scan records with target, status, findings, and risk." icon={<Activity className="h-5 w-5" />}>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="border-b border-border text-xs font-semibold text-muted-foreground">
                <tr>
                  <th className="py-3 pr-4">Scan</th>
                  <th className="py-3 pr-4">Target</th>
                  <th className="py-3 pr-4">Profile</th>
                  <th className="py-3 pr-4">Status</th>
                  <th className="py-3 pr-4">Findings</th>
                  <th className="py-3">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {summary.recent_scans.map(scan => (
                  <tr key={scan.id} className="hover:bg-muted/30">
                    <td className="py-4 pr-4 font-semibold">#{scan.id}</td>
                    <td className="py-4 pr-4">{targets.find(target => target.id === scan.target_id)?.name || `Target #${scan.target_id}`}</td>
                    <td className="py-4 pr-4 text-muted-foreground">{scan.profile}</td>
                    <td className="py-4 pr-4"><StatusBadge status={scan.status} /></td>
                    <td className="py-4 pr-4 font-semibold">{scan.status === 'completed' ? scan.total_findings : '-'}</td>
                    <td className="py-4">{scan.status === 'completed' ? <RiskScoreBadge score={scan.risk_score} /> : <span className="text-muted-foreground">N/A</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>

        <SectionCard title="Policy Coverage" subtitle={`${policies.length} packs, ${policyCheckCount} checks mapped.`} icon={<ShieldCheck className="h-5 w-5" />}>
          <div className="space-y-3">
            {policies.map(policy => (
              <div key={policy.policy_id} className="rounded-md border border-border bg-background/60 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="font-semibold">{policy.title}</h3>
                    <p className="mt-1 text-xs text-muted-foreground">{policy.policy_id}</p>
                  </div>
                  <span className="rounded-full bg-muted px-2.5 py-1 text-xs font-medium">{policy.checks.length} checks</span>
                </div>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{policy.description}</p>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Recent Findings" subtitle="Evidence-backed issues from the latest assessments." icon={<ShieldAlert className="h-5 w-5" />}>
        {recentFindings.length > 0 ? (
          <div className="grid gap-4 xl:grid-cols-2">
            {recentFindings.map(finding => <FindingCard key={finding.id} finding={finding} compact />)}
          </div>
        ) : (
          <EmptyState title="No findings yet" description="Completed scans with detected issues will appear here." />
        )}
      </SectionCard>
    </PageShell>
  );
}
