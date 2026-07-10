import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ArrowLeft, Copy, Download, Eye, ExternalLink, FileText, RefreshCw, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import type { Finding, Report, Scan, Target } from '../types';
import { vulnscopeApi } from '../api/vulnscope';
import { EmptyState, PageHeader, PageShell, RiskScoreBadge, SectionCard } from '../components/ui';

export function Reports() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [reports, setReports] = useState<Report[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [findingsByScan, setFindingsByScan] = useState<Record<number, Finding[]>>({});
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [apiReports, apiScans, apiTargets] = await Promise.all([
        vulnscopeApi.listReports(),
        vulnscopeApi.listScans(),
        vulnscopeApi.listTargets(),
      ]);
      const scanIds = [...new Set(apiReports.map(report => report.scan_id))];
      const findings = await Promise.all(scanIds.map(async scanId => [scanId, await vulnscopeApi.listFindings(scanId)] as const));
      setReports(apiReports);
      setScans(apiScans);
      setTargets(apiTargets);
      setFindingsByScan(Object.fromEntries(findings));
    } catch {
      setError('Reports could not be loaded from the backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadReports();
  }, [loadReports]);

  const openPreview = useCallback(async (reportId: number) => {
    setPreviewLoading(true);
    try {
      const report = await vulnscopeApi.getReport(reportId);
      setSelectedReport(report);
      setSearchParams({ reportId: report.id.toString() });
    } catch {
      toast.error('Unable to open this report.');
    } finally {
      setPreviewLoading(false);
    }
  }, [setSearchParams]);

  useEffect(() => {
    const reportId = Number(searchParams.get('reportId'));
    if (reportId && selectedReport?.id !== reportId) void openPreview(reportId);
  }, [openPreview, searchParams, selectedReport?.id]);

  const reportMetrics = (report: Report) => {
    const scan = scans.find(item => item.id === report.scan_id);
    const findings = findingsByScan[report.scan_id] || [];
    return {
      scan,
      target: targets.find(item => item.id === report.target_id),
      findings: findings.length,
      priority: findings.filter(item => item.severity === 'critical' || item.severity === 'high').length,
      risk: scan?.risk_score ?? 0,
    };
  };

  const reportBlob = async (report: Report) => {
    try {
      return await vulnscopeApi.downloadReport(report.id);
    } catch {
      toast.error('Unable to retrieve the report file.');
      return null;
    }
  };

  const handleDownload = async (report: Report) => {
    const blob = await reportBlob(report);
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `vulnscope-report-${report.id}.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast.success('Report download started.');
  };

  const openInNewTab = async (report: Report) => {
    const previewWindow = window.open('', '_blank');
    if (previewWindow) previewWindow.opener = null;
    const blob = await reportBlob(report);
    if (!blob) {
      previewWindow?.close();
      return;
    }
    const url = URL.createObjectURL(blob);
    if (previewWindow) previewWindow.location.href = url;
    else toast.error('Allow pop-ups to open the report in a new tab.');
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  };

  const closePreview = () => {
    setSelectedReport(null);
    setSearchParams({});
  };

  const removeReport = async (report: Report) => {
    if (!confirm(`Delete "${report.title}"?`)) return;
    try {
      await vulnscopeApi.deleteReport(report.id);
      setReports(current => current.filter(item => item.id !== report.id));
      if (selectedReport?.id === report.id) closePreview();
      toast.success('Report deleted.');
    } catch {
      toast.error('Report could not be deleted.');
    }
  };

  if (selectedReport) {
    const metrics = reportMetrics(selectedReport);
    return (
      <PageShell className="max-w-none">
        <button onClick={closePreview} className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" /> Back to Reports
        </button>
        <div className="grid gap-6 xl:grid-cols-[360px_1fr]">
          <SectionCard title="Report Details" subtitle="Generated assessment content from the VulnScope backend.">
            <div className="space-y-5">
              <div>
                <h1 className="text-2xl font-semibold">{selectedReport.title}</h1>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{selectedReport.executive_summary}</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Metric label="Target" value={metrics.target?.name || 'Unknown'} />
                <Metric label="Profile" value={metrics.scan?.profile || 'Unknown'} />
                <Metric label="Findings" value={metrics.findings.toString()} />
                <Metric label="Critical / High" value={metrics.priority.toString()} />
              </div>
              <RiskScoreBadge score={metrics.risk} />
              <div className="flex flex-col gap-2">
                <button onClick={() => { void navigator.clipboard.writeText(selectedReport.executive_summary); toast.success('Summary copied.'); }} className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-border text-sm font-semibold hover:bg-muted"><Copy className="h-4 w-4" /> Copy Summary</button>
                <button onClick={() => void openInNewTab(selectedReport)} className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-border text-sm font-semibold hover:bg-muted"><ExternalLink className="h-4 w-4" /> Open in New Tab</button>
                <button onClick={() => void handleDownload(selectedReport)} className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-primary text-sm font-semibold text-primary-foreground hover:bg-primary/90"><Download className="h-4 w-4" /> Download HTML</button>
                <button onClick={() => void removeReport(selectedReport)} className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-red-400/40 text-sm font-semibold text-red-300 hover:bg-red-500/10"><Trash2 className="h-4 w-4" /> Delete Report</button>
              </div>
            </div>
          </SectionCard>
          <div className="min-h-[70vh] overflow-hidden rounded-lg border border-border bg-white shadow-lg shadow-black/20">
            <iframe srcDoc={selectedReport.html_content} className="h-full min-h-[70vh] w-full bg-white" title={`Report ${selectedReport.id}`} sandbox="allow-same-origin" />
          </div>
        </div>
      </PageShell>
    );
  }

  return (
    <PageShell>
      <PageHeader title="Assessment Reports" subtitle="Generated Web Exposure assessment reports, ready to review or export." actions={<button onClick={() => void loadReports()} disabled={loading} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted disabled:opacity-50"><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Refresh</button>} />
      {loading && <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">Loading reports...</div>}
      {!loading && error && <EmptyState title="Reports unavailable" description={error} action={<button onClick={() => void loadReports()} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Try Again</button>} />}
      {!loading && !error && reports.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-2">
          {reports.map(report => {
            const metrics = reportMetrics(report);
            return (
              <article key={report.id} role="button" tabIndex={0} onClick={() => void openPreview(report.id)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') void openPreview(report.id); }} className="flex min-h-[260px] cursor-pointer flex-col rounded-lg border border-border bg-card/90 p-5 shadow-sm transition-colors hover:border-primary/60 focus:outline-none focus:ring-2 focus:ring-primary">
                <div className="flex items-start justify-between gap-4">
                  <div className="rounded-md bg-primary/15 p-3 text-primary"><FileText className="h-5 w-5" /></div>
                  <span className="text-sm text-muted-foreground">{new Date(report.created_at).toLocaleDateString()}</span>
                </div>
                <h2 className="mt-4 text-lg font-semibold">{report.title}</h2>
                <p className="mt-2 line-clamp-2 text-sm leading-6 text-muted-foreground">{report.executive_summary}</p>
                <div className="mt-5 grid gap-3 sm:grid-cols-2">
                  <Metric label="Target" value={metrics.target?.name || 'Unknown target'} />
                  <Metric label="Scan Profile" value={metrics.scan?.profile || 'Unknown profile'} />
                  <Metric label="Findings" value={metrics.findings.toString()} />
                  <Metric label="Critical / High" value={metrics.priority.toString()} />
                </div>
                <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                  <RiskScoreBadge score={metrics.risk} />
                  <div className="flex gap-2">
                    <button onClick={event => { event.stopPropagation(); void openPreview(report.id); }} disabled={previewLoading} className="inline-flex h-10 items-center gap-2 rounded-md bg-secondary px-4 text-sm font-semibold text-secondary-foreground hover:bg-secondary/80"><Eye className="h-4 w-4" /> View</button>
                    <button onClick={event => { event.stopPropagation(); void handleDownload(report); }} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted"><Download className="h-4 w-4" /> Export</button>
                    <button onClick={event => { event.stopPropagation(); void removeReport(report); }} title="Delete report" className="inline-flex h-10 w-10 items-center justify-center rounded-md border border-border text-muted-foreground hover:border-red-400/50 hover:bg-red-500/10 hover:text-red-300"><Trash2 className="h-4 w-4" /></button>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}
      {!loading && !error && reports.length === 0 && <EmptyState title="No reports yet" description="Generate a report from a completed scan to see it here." />}
    </PageShell>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="rounded-md border border-border bg-background/60 p-3"><p className="text-xs font-medium text-muted-foreground">{label}</p><p className="mt-1 line-clamp-2 text-sm font-semibold leading-5">{value}</p></div>;
}
