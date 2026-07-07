import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowRight, FileText, Plus, ShieldAlert, ShieldCheck, Target as TargetIcon, Trash2 } from 'lucide-react';
import type { Target } from '../types';
import { createTarget as createDemoTarget, deleteTarget as deleteDemoTarget, getTargets, listFindings, listReports, listScans } from '../data/demoData';
import { EmptyState, FindingCard, PageHeader, PageShell, RiskScoreBadge, SectionCard, SeverityBadge, StatCard, StatusBadge } from '../components/ui';

export function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    base_url: '',
    environment: 'development',
    authorization_confirmed: false,
  });

  const fetchTargets = () => {
    const items = getTargets();
    setTargets(items);
    setSelectedTargetId(current => current || items[0]?.id || null);
    setLoading(false);
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.authorization_confirmed) return;
    createDemoTarget(formData);
    setShowForm(false);
    setFormData({ name: '', base_url: '', environment: 'development', authorization_confirmed: false });
    fetchTargets();
  };

  const deleteTarget = (event: React.MouseEvent, id: number) => {
    event.stopPropagation();
    if (!confirm('Are you sure you want to delete this target?')) return;
    deleteDemoTarget(id);
    setSelectedTargetId(current => current === id ? null : current);
    fetchTargets();
  };

  const scans = listScans();
  const reports = listReports();
  const selectedTarget = targets.find(target => target.id === selectedTargetId) || targets[0] || null;
  const selectedScans = selectedTarget ? scans.filter(scan => scan.target_id === selectedTarget.id) : [];
  const latestScan = selectedScans[0] || null;
  const latestFindings = latestScan ? listFindings(latestScan.id).slice(0, 3) : [];
  const targetReports = selectedTarget ? reports.filter(report => report.target_id === selectedTarget.id) : [];

  const targetMetrics = (target: Target) => {
    const targetScans = scans.filter(scan => scan.target_id === target.id);
    const latest = targetScans[0] || null;
    const targetReports = reports.filter(report => report.target_id === target.id);
    return {
      scanCount: targetScans.length,
      findingCount: targetScans.reduce((total, scan) => total + scan.total_findings, 0),
      reportCount: targetReports.length,
      latest,
      risk: latest?.risk_score ?? 0,
    };
  };

  return (
    <PageShell>
      <PageHeader
        title="Targets"
        subtitle="Demo data. Manage authorized web assets and review each target's latest posture, findings, scans, and reports."
        actions={
          <button onClick={() => setShowForm(value => !value)} className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:bg-primary/90">
            <Plus className="h-4 w-4" /> Add Target
          </button>
        }
      />

      {showForm && (
        <SectionCard title="Add New Target" subtitle="Only add systems you own or are explicitly authorized to assess.">
          <form onSubmit={handleSubmit} className="grid gap-4 lg:grid-cols-2">
            <label className="space-y-2 text-sm font-medium">
              Target Name
              <input required className="h-10 w-full rounded-md border border-input bg-background px-3" value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })} />
            </label>
            <label className="space-y-2 text-sm font-medium">
              Base URL
              <input required type="url" placeholder="https://example.com" className="h-10 w-full rounded-md border border-input bg-background px-3" value={formData.base_url} onChange={e => setFormData({ ...formData, base_url: e.target.value })} />
            </label>
            <label className="space-y-2 text-sm font-medium">
              Environment
              <select className="h-10 w-full rounded-md border border-input bg-background px-3" value={formData.environment} onChange={e => setFormData({ ...formData, environment: e.target.value })}>
                <option value="development">Development</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
                <option value="public">Public</option>
              </select>
            </label>
            <label className="flex items-start gap-3 rounded-md border border-red-400/30 bg-red-500/5 p-4 text-sm leading-6 text-muted-foreground lg:col-span-2">
              <input required type="checkbox" className="mt-1" checked={formData.authorization_confirmed} onChange={e => setFormData({ ...formData, authorization_confirmed: e.target.checked })} />
              <span><strong className="block text-foreground">Authorization Confirmation</strong>I own this system or have explicit permission to conduct safe security testing on this target.</span>
            </label>
            <div className="flex justify-end gap-3 lg:col-span-2">
              <button type="button" onClick={() => setShowForm(false)} className="h-10 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted">Cancel</button>
              <button type="submit" disabled={!formData.authorization_confirmed} className="h-10 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:bg-primary/90 disabled:opacity-50">Save Target</button>
            </div>
          </form>
        </SectionCard>
      )}

      {selectedTarget && (
        <SectionCard title="Selected Target" subtitle="Current target details and latest assessment signals." icon={<TargetIcon className="h-5 w-5" />}>
          <div className="grid gap-6 xl:grid-cols-[1fr_320px]">
            <div className="space-y-5">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <h2 className="text-2xl font-semibold">{selectedTarget.name}</h2>
                  <p className="mt-1 break-all font-mono text-sm text-muted-foreground">{selectedTarget.base_url}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <span className="rounded-full border border-border bg-muted px-3 py-1 text-xs font-medium capitalize">{selectedTarget.environment}</span>
                    <StatusBadge status={selectedTarget.authorization_confirmed ? 'authorized' : 'unauthorized'} />
                  </div>
                </div>
                <Link to={`/scans/new?targetId=${selectedTarget.id}`} className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:bg-primary/90">
                  New Scan <ArrowRight className="h-4 w-4" />
                </Link>
              </div>

              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <StatCard label="Scans" value={selectedScans.length} icon={<Activity className="h-5 w-5" />} tone="info" />
                <StatCard label="Findings" value={selectedScans.reduce((total, scan) => total + scan.total_findings, 0)} icon={<ShieldAlert className="h-5 w-5" />} tone="warn" />
                <StatCard label="Reports" value={targetReports.length} icon={<FileText className="h-5 w-5" />} />
                <StatCard label="Latest Posture" value={latestScan ? `${latestScan.overall_posture_score}/100` : '-'} icon={<ShieldCheck className="h-5 w-5" />} tone="good" />
              </div>

              {latestScan ? (
                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="rounded-lg border border-border bg-background/60 p-4">
                    <div className="mb-4 flex items-start justify-between gap-3">
                      <div>
                        <h3 className="font-semibold">Latest scan</h3>
                        <p className="mt-1 text-sm text-muted-foreground">#{latestScan.id} · {latestScan.profile}</p>
                      </div>
                      <StatusBadge status={latestScan.status} />
                    </div>
                    <RiskScoreBadge score={latestScan.risk_score} />
                    <p className="mt-3 text-sm text-muted-foreground">Completed {latestScan.completed_at ? new Date(latestScan.completed_at).toLocaleString() : 'not yet completed'}</p>
                  </div>
                  <div className="rounded-lg border border-border bg-background/60 p-4">
                    <h3 className="mb-3 font-semibold">Latest findings</h3>
                    <div className="space-y-3">
                      {latestFindings.length > 0 ? latestFindings.map(finding => (
                        <div key={finding.id} className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-sm font-medium">{finding.title}</p>
                            <p className="text-xs text-muted-foreground">{finding.category}</p>
                          </div>
                          <SeverityBadge severity={finding.severity} />
                        </div>
                      )) : <p className="text-sm text-muted-foreground">No findings for the latest scan.</p>}
                    </div>
                  </div>
                </div>
              ) : (
                <EmptyState title="No scans for this target" description="Start a scan to populate posture, findings, and report data." action={<Link to={`/scans/new?targetId=${selectedTarget.id}`} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Start Scan</Link>} />
              )}
            </div>

            <div className="space-y-4">
              <div className="rounded-lg border border-border bg-background/60 p-4">
                <h3 className="mb-3 font-semibold">Target metadata</h3>
                <dl className="space-y-3 text-sm">
                  <div><dt className="text-muted-foreground">Domain</dt><dd className="mt-1 break-all font-medium">{selectedTarget.domain}</dd></div>
                  <div><dt className="text-muted-foreground">Created</dt><dd className="mt-1 font-medium">{new Date(selectedTarget.created_at).toLocaleDateString()}</dd></div>
                  <div><dt className="text-muted-foreground">Authorization</dt><dd className="mt-1 font-medium">{selectedTarget.authorization_confirmed ? 'Confirmed' : 'Not confirmed'}</dd></div>
                </dl>
              </div>
              <div className="rounded-lg border border-border bg-background/60 p-4">
                <h3 className="mb-3 font-semibold">Reports</h3>
                <div className="space-y-3">
                  {targetReports.slice(0, 3).map(report => (
                    <Link key={report.id} to="/reports" className="block rounded-md border border-border bg-card/70 p-3 hover:bg-muted/40">
                      <p className="text-sm font-medium">{report.title}</p>
                      <p className="mt-1 line-clamp-2 text-xs leading-5 text-muted-foreground">{report.executive_summary}</p>
                    </Link>
                  ))}
                  {targetReports.length === 0 && <p className="text-sm text-muted-foreground">No reports for this target yet.</p>}
                </div>
              </div>
            </div>
          </div>
        </SectionCard>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {targets.map(target => {
          const metrics = targetMetrics(target);
          const selected = selectedTarget?.id === target.id;
          return (
            <button key={target.id} type="button" onClick={() => setSelectedTargetId(target.id)} className={`group flex min-h-[250px] flex-col rounded-lg border bg-card/90 p-5 text-left shadow-sm transition-all hover:border-primary/60 ${selected ? 'border-primary shadow-[0_0_0_1px_rgba(34,197,94,0.35),0_0_24px_rgba(34,197,94,0.08)]' : 'border-border'}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <h3 className="text-lg font-semibold">{target.name}</h3>
                  <p className="mt-1 break-all font-mono text-xs leading-5 text-muted-foreground">{target.base_url}</p>
                </div>
                <span onClick={(event) => deleteTarget(event, target.id)} className="rounded-md p-2 text-muted-foreground opacity-0 transition hover:bg-red-500/10 hover:text-red-300 group-hover:opacity-100">
                  <Trash2 className="h-4 w-4" />
                </span>
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <span className="rounded-full border border-border bg-muted px-3 py-1 text-xs font-medium capitalize">{target.environment}</span>
                <StatusBadge status={target.authorization_confirmed ? 'authorized' : 'unauthorized'} />
              </div>
              <div className="mt-auto grid grid-cols-3 gap-3 pt-5 text-sm">
                <Metric label="Scans" value={metrics.scanCount} />
                <Metric label="Findings" value={metrics.findingCount} />
                <Metric label="Reports" value={metrics.reportCount} />
              </div>
              <div className="mt-4 border-t border-border pt-4">
                {metrics.latest ? (
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground">Latest scan</p>
                      <p className="text-sm font-medium">#{metrics.latest.id} · {new Date(metrics.latest.started_at).toLocaleDateString()}</p>
                    </div>
                    <RiskScoreBadge score={metrics.risk} />
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No scans yet</p>
                )}
              </div>
            </button>
          );
        })}
      </div>

      {!loading && targets.length === 0 && (
        <EmptyState title="No targets yet" description="Add an authorized target to begin a safe assessment workflow." icon={<AlertTriangle className="h-8 w-8" />} action={<button onClick={() => setShowForm(true)} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Add Target</button>} />
      )}

      {latestFindings.length > 0 && (
        <SectionCard title="Finding Preview" subtitle="Recent findings for the selected target.">
          <div className="grid gap-4 xl:grid-cols-3">
            {latestFindings.map(finding => <FindingCard key={finding.id} finding={finding} compact />)}
          </div>
        </SectionCard>
      )}
    </PageShell>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background/60 p-3">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 text-lg font-semibold">{value}</p>
    </div>
  );
}
