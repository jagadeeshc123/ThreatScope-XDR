import { useEffect, useState } from 'react';
import { ArrowLeft, Copy, Download, Eye, FileText } from 'lucide-react';
import type { Report } from '../types';
import { getReportHtml, getTargets, listFindings, listReports, listScans } from '../data/demoData';
import { EmptyState, PageHeader, PageShell, RiskScoreBadge, SectionCard } from '../components/ui';

export function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedHtml, setSelectedHtml] = useState<string | null>(null);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);

  useEffect(() => {
    setReports(listReports());
    setLoading(false);
  }, []);

  const scans = listScans();
  const targets = getTargets();

  const reportMetrics = (report: Report) => {
    const scan = scans.find(item => item.id === report.scan_id);
    const target = targets.find(item => item.id === report.target_id);
    const findings = scan ? listFindings(scan.id) : [];
    return {
      scan,
      target,
      findings: findings.length,
      priority: findings.filter(item => item.severity === 'critical' || item.severity === 'high').length,
      risk: scan?.risk_score ?? 0,
    };
  };

  const handleDownload = (report: Report) => {
    const blob = new Blob([getReportHtml(report.id) || report.html_content], { type: 'text/html' });
    window.open(URL.createObjectURL(blob), '_blank');
  };

  const openPreview = (report: Report) => {
    setSelectedReport(report);
    setSelectedHtml(getReportHtml(report.id) || report.html_content);
  };

  if (selectedHtml && selectedReport) {
    const metrics = reportMetrics(selectedReport);
    return (
      <PageShell className="max-w-none">
        <button onClick={() => { setSelectedHtml(null); setSelectedReport(null); }} className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" /> Back to Reports
        </button>
        <div className="grid gap-6 xl:grid-cols-[360px_1fr]">
          <SectionCard title="Report Preview" subtitle="Demo data. Review summary and open the generated HTML output.">
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
                <button onClick={() => navigator.clipboard.writeText(selectedReport.executive_summary)} className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-border text-sm font-semibold hover:bg-muted"><Copy className="h-4 w-4" /> Copy Summary</button>
                <button onClick={() => handleDownload(selectedReport)} className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-primary text-sm font-semibold text-primary-foreground hover:bg-primary/90"><Download className="h-4 w-4" /> Export HTML</button>
              </div>
            </div>
          </SectionCard>
          <div className="min-h-[70vh] overflow-hidden rounded-lg border border-border bg-white shadow-lg shadow-black/20">
            <iframe srcDoc={selectedHtml} className="h-full min-h-[70vh] w-full bg-white" title="Report Preview" />
          </div>
        </div>
      </PageShell>
    );
  }

  return (
    <PageShell>
      <PageHeader title="Assessment Reports" subtitle="Demo data. Professional report cards with target, profile, date, findings, risk score, and export actions." />
      <div className="grid gap-4 lg:grid-cols-2">
        {reports.map(report => {
          const metrics = reportMetrics(report);
          return (
            <article key={report.id} className="flex min-h-[260px] flex-col rounded-lg border border-border bg-card/90 p-5 shadow-sm">
              <div className="flex items-start justify-between gap-4">
                <div className="rounded-md bg-primary/15 p-3 text-primary"><FileText className="h-5 w-5" /></div>
                <span className="text-sm text-muted-foreground">{new Date(report.created_at).toLocaleDateString()}</span>
              </div>
              <h2 className="mt-4 text-lg font-semibold">{report.title}</h2>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">{report.executive_summary}</p>
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                <Metric label="Target" value={metrics.target?.name || 'Unknown target'} />
                <Metric label="Scan Profile" value={metrics.scan?.profile || 'Unknown profile'} />
                <Metric label="Findings" value={metrics.findings.toString()} />
                <Metric label="Critical / High" value={metrics.priority.toString()} />
              </div>
              <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                <RiskScoreBadge score={metrics.risk} />
                <div className="flex gap-2">
                  <button onClick={() => openPreview(report)} className="inline-flex h-10 items-center gap-2 rounded-md bg-secondary px-4 text-sm font-semibold text-secondary-foreground hover:bg-secondary/80"><Eye className="h-4 w-4" /> View</button>
                  <button onClick={() => handleDownload(report)} className="inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted"><Download className="h-4 w-4" /> Export</button>
                </div>
              </div>
            </article>
          );
        })}
      </div>
      {!loading && reports.length === 0 && (
        <EmptyState title="No reports yet" description="Completed demo scans can generate assessment reports." />
      )}
    </PageShell>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-background/60 p-3">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <p className="mt-1 line-clamp-2 text-sm font-semibold leading-5">{value}</p>
    </div>
  );
}
