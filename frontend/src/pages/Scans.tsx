import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Activity, ArrowLeft, Camera, CheckCircle2, ChevronDown, ChevronRight, Download, ExternalLink, Eye, FileText, GitMerge, Maximize2, Play, ShieldCheck, Trash2, XCircle, ZoomIn, ZoomOut } from 'lucide-react';
import { toast } from 'sonner';
import type { CrawlNode, EvidenceArtifact, Finding, PostureDiff, Report, Scan, Target } from '../types';
import { vulnscopeApi, type PolicyResultPack } from '../api/vulnscope';
import { EmptyState, FindingCard, PageHeader, PageShell, RiskScoreBadge, SectionCard, StatCard, StatusBadge } from '../components/ui';

type Tab = 'findings' | 'crawlMap' | 'drift' | 'evidence' | 'policies';

function isTab(value: string | null): value is Tab {
  return value === 'findings' || value === 'crawlMap' || value === 'drift' || value === 'evidence' || value === 'policies';
}

export function Scans() {
  const [searchParams] = useSearchParams();
  const initialTargetId = searchParams.get('targetId');
  const highlightScanId = searchParams.get('highlight');
  const requestedTab = searchParams.get('tab');
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [showNewScan, setShowNewScan] = useState(!!initialTargetId);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [crawlNodes, setCrawlNodes] = useState<CrawlNode[]>([]);
  const [postureDiff, setPostureDiff] = useState<PostureDiff | null>(null);
  const [evidence, setEvidence] = useState<EvidenceArtifact[]>([]);
  const [policyResults, setPolicyResults] = useState<PolicyResultPack[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [downloadingReport, setDownloadingReport] = useState(false);
  const [showReportMenu, setShowReportMenu] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>(isTab(requestedTab) ? requestedTab : 'findings');
  const [formData, setFormData] = useState({ target_id: initialTargetId || '', profile: 'Standard Safe Scan' });
  const reportMenuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [apiScans, apiTargets] = await Promise.all([
        vulnscopeApi.listScans(),
        vulnscopeApi.listTargets(),
      ]);
      setScans(apiScans);
      setTargets(apiTargets);
      setFormData(current => !current.target_id && apiTargets.length > 0
        ? { ...current, target_id: apiTargets[0].id.toString() }
        : current);
    } catch {
      setError('Scans and targets could not be loaded from the backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchData();
  }, [fetchData]);

  const hasActiveScans = scans.some(scan => scan.status === 'queued' || scan.status === 'running');
  useEffect(() => {
    if (!hasActiveScans) return;
    const interval = window.setInterval(() => void fetchData(), 3000);
    return () => window.clearInterval(interval);
  }, [fetchData, hasActiveScans]);

  useEffect(() => {
    if (!showReportMenu) return;
    const closeMenu = (event: MouseEvent) => {
      if (reportMenuRef.current && !reportMenuRef.current.contains(event.target as Node)) setShowReportMenu(false);
    };
    document.addEventListener('mousedown', closeMenu);
    return () => document.removeEventListener('mousedown', closeMenu);
  }, [showReportMenu]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await vulnscopeApi.startScan({ target_id: Number(formData.target_id), profile: formData.profile });
      toast.success('Scan started.');
      setShowNewScan(false);
      await fetchData();
    } catch {
      toast.error('Scan could not be started.');
    }
  };

  const loadScanDetails = useCallback(async (scan: Scan) => {
    setSelectedScan(scan);
    setActiveTab(isTab(requestedTab) ? requestedTab : 'findings');
    setFindings([]);
    setCrawlNodes([]);
    setEvidence([]);
    setPolicyResults([]);
    setPostureDiff(null);
    setReport(null);
    setShowReportMenu(false);
    if (scan.status !== 'completed') {
      setDetailsLoading(false);
      setDetailError(null);
      return;
    }
    setDetailsLoading(true);
    setDetailError(null);
    try {
      const [apiFindings, apiCrawlNodes, apiEvidence, apiPolicyResults, apiPostureDiff, reports] = await Promise.all([
        vulnscopeApi.listFindings(scan.id),
        vulnscopeApi.listCrawlNodes(scan.id),
        vulnscopeApi.listEvidence(scan.id),
        vulnscopeApi.getPolicyResults(scan.id),
        vulnscopeApi.getPostureDiff(scan.id).catch(() => null),
        vulnscopeApi.listReports(),
      ]);
      setFindings(apiFindings);
      setCrawlNodes(apiCrawlNodes);
      setEvidence(apiEvidence);
      setPolicyResults(apiPolicyResults);
      setPostureDiff(apiPostureDiff);
      setReport(reports.find(item => item.scan_id === scan.id) || null);
    } catch {
      setDetailError('Scan details could not be loaded from the backend.');
    } finally {
      setDetailsLoading(false);
    }
  }, [requestedTab]);

  useEffect(() => {
    if (!highlightScanId || scans.length === 0) return;
    const scan = scans.find(item => item.id.toString() === highlightScanId);
    if (scan) void loadScanDetails(scan);
  }, [highlightScanId, scans, loadScanDetails]);

  const getTargetName = (id: number) => targets.find(target => target.id === id)?.name || `Target #${id}`;

  const ensureReport = async (notify = true): Promise<Report | null> => {
    if (report) return report;
    if (!selectedScan) return null;
    setGeneratingReport(true);
    try {
      const generated = await vulnscopeApi.generateReport(selectedScan.id);
      setReport(generated);
      if (notify) toast.success('Report is ready.');
      return generated;
    } catch {
      toast.error('Report generation failed.');
      return null;
    } finally {
      setGeneratingReport(false);
    }
  };

  const handleGenerateReport = async () => {
    await ensureReport();
    setShowReportMenu(false);
  };

  const handleDownloadReport = async () => {
    setDownloadingReport(true);
    try {
      const currentReport = await ensureReport(false);
      if (!currentReport) return;
      const blob = await vulnscopeApi.downloadReport(currentReport.id);
      if (blob.size === 0) throw new Error('Empty report response');
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `vulnscope-scan-${currentReport.scan_id}-report.html`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setShowReportMenu(false);
      toast.success('Report download started.');
    } catch {
      toast.error('Report download failed.');
    } finally {
      setDownloadingReport(false);
    }
  };

  const handleViewReport = async () => {
    const currentReport = await ensureReport(false);
    if (!currentReport) return;
    setShowReportMenu(false);
    navigate(`/reports?reportId=${currentReport.id}`);
  };

  const retryScan = async () => {
    if (!selectedScan) return;
    setRetrying(true);
    try {
      const scan = await vulnscopeApi.startScan({ target_id: selectedScan.target_id, profile: selectedScan.profile });
      toast.success('Scan retry started.');
      setSelectedScan(null);
      navigate(`/scans?highlight=${scan.id}`);
      await fetchData();
    } catch {
      toast.error('Scan retry could not be started.');
    } finally {
      setRetrying(false);
    }
  };

  const removeScan = async (event: React.MouseEvent, scan: Scan) => {
    event.stopPropagation();
    if (scan.status === 'queued' || scan.status === 'running') {
      toast.error('Active scans cannot be deleted.');
      return;
    }
    if (!confirm(`Delete scan #${scan.id} and all of its findings, evidence, drift, and reports?`)) return;
    try {
      await vulnscopeApi.deleteScan(scan.id);
      if (selectedScan?.id === scan.id) setSelectedScan(null);
      toast.success(`Scan #${scan.id} deleted.`);
      await fetchData();
    } catch {
      toast.error('Scan could not be deleted.');
    }
  };

  if (selectedScan) {
    if (selectedScan.status !== 'completed') {
      const failed = selectedScan.status === 'failed';
      return (
        <PageShell>
          <button onClick={() => setSelectedScan(null)} className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground"><ArrowLeft className="h-4 w-4" /> Back to Scans</button>
          <PageHeader title={`Scan Details #${selectedScan.id}`} subtitle={`${getTargetName(selectedScan.target_id)} - ${selectedScan.profile}`} actions={<StatusBadge status={selectedScan.status} />} />
          <EmptyState
            title={failed ? 'Scan could not reach the target' : 'Scan is processing'}
            description={failed ? (selectedScan.error_message || 'The scanner stopped before assessment results were produced.') : 'This page refreshes automatically while the backend scanner is running.'}
            action={failed ? <button onClick={() => void retryScan()} disabled={retrying} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">{retrying ? 'Retrying...' : 'Retry Scan'}</button> : undefined}
          />
          <p className="text-center text-sm text-muted-foreground">Posture, risk, findings, crawl map, evidence, drift, policies, and reports are available only after a scan completes.</p>
        </PageShell>
      );
    }
    return (
      <PageShell>
        <button onClick={() => setSelectedScan(null)} className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" /> Back to Scans
        </button>

        <PageHeader
          title={`Scan Details #${selectedScan.id}`}
          subtitle={`${getTargetName(selectedScan.target_id)} - ${selectedScan.profile} - Backend data`}
          actions={<StatusBadge status={selectedScan.status} />}
        />

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Posture Score" value={<>{selectedScan.overall_posture_score}<span className="text-base text-muted-foreground">/100</span></>} tone="good" icon={<ShieldCheck className="h-5 w-5" />} />
          <StatCard label="Risk Score" value={<>{selectedScan.risk_score.toFixed(1)}<span className="text-base text-muted-foreground">/10</span></>} tone={selectedScan.risk_score >= 6 ? 'danger' : 'warn'} icon={<Activity className="h-5 w-5" />} />
          <StatCard label="Findings" value={selectedScan.total_findings} tone="warn" icon={<FileText className="h-5 w-5" />} />
          <div className="rounded-lg border border-border bg-card/90 p-5">
            <p className="text-sm font-medium text-muted-foreground">Report</p>
            <p className="mt-4 text-sm leading-6 text-muted-foreground">{report ? 'A generated report is ready to review.' : 'Generate an HTML assessment report for this scan.'}</p>
            {report ? <Link to={`/reports?reportId=${report.id}`} className="mt-4 inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted">View Report <ChevronRight className="h-4 w-4" /></Link> : <button onClick={() => void handleGenerateReport()} disabled={generatingReport || selectedScan.status !== 'completed'} className="mt-4 inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted disabled:opacity-50">{generatingReport ? 'Generating...' : 'Generate Report'}</button>}
          </div>
        </div>

        {detailsLoading && <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">Loading scan evidence and results...</div>}
        {!detailsLoading && detailError && <EmptyState title="Scan details unavailable" description={detailError} action={<button onClick={() => void loadScanDetails(selectedScan)} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Try Again</button>} />}

        {!detailsLoading && !detailError && <SectionCard title="Security Posture Breakdown" subtitle="Category scores captured by the selected scan.">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <PostureMetric label="Transport" value={selectedScan.posture_transport_security} />
            <PostureMetric label="Browser" value={selectedScan.posture_browser_defense} />
            <PostureMetric label="Session" value={selectedScan.posture_session_safety} />
            <PostureMetric label="Exposure" value={selectedScan.posture_exposure_hygiene} />
            <PostureMetric label="Auth Surface" value={selectedScan.posture_authentication_surface} />
          </div>
        </SectionCard>}

        <div className="flex items-end justify-between gap-4 border-b border-border">
          <nav className="flex min-w-0 flex-1 gap-6 overflow-x-auto">
            <TabButton active={activeTab === 'findings'} onClick={() => setActiveTab('findings')}>Findings</TabButton>
            <TabButton active={activeTab === 'crawlMap'} onClick={() => setActiveTab('crawlMap')} icon={<GitMerge className="h-4 w-4" />}>Crawl Map</TabButton>
            <TabButton active={activeTab === 'drift'} onClick={() => setActiveTab('drift')}>Posture Drift</TabButton>
            <TabButton active={activeTab === 'evidence'} onClick={() => setActiveTab('evidence')} icon={<Camera className="h-4 w-4" />}>Evidence</TabButton>
            <TabButton active={activeTab === 'policies'} onClick={() => setActiveTab('policies')} icon={<ShieldCheck className="h-4 w-4" />}>Policy Results</TabButton>
          </nav>
          <div ref={reportMenuRef} className="relative shrink-0 pb-2">
            <div className="inline-flex overflow-hidden rounded-md bg-primary text-primary-foreground">
              <button type="button" onClick={() => void handleDownloadReport()} disabled={generatingReport || downloadingReport} aria-label={`Download report for scan ${selectedScan.id}`} className="inline-flex h-9 items-center gap-2 whitespace-nowrap px-3 text-sm font-semibold hover:bg-primary/90 disabled:opacity-50">
                <Download className="h-4 w-4" />
                {downloadingReport ? 'Preparing...' : 'Download Report'}
              </button>
              <button type="button" onClick={() => setShowReportMenu(value => !value)} disabled={generatingReport || downloadingReport} aria-label="More report actions" aria-haspopup="menu" aria-expanded={showReportMenu} className="inline-flex h-9 w-9 items-center justify-center border-l border-primary-foreground/25 hover:bg-primary/90 disabled:opacity-50">
                <ChevronDown className="h-3.5 w-3.5" />
              </button>
            </div>
            {showReportMenu && (
              <div role="menu" className="absolute right-0 top-full z-40 mt-1 w-56 overflow-hidden rounded-md border border-border bg-card p-1 shadow-xl shadow-black/30">
                <button role="menuitem" type="button" onClick={() => void handleDownloadReport()} className="flex w-full items-center gap-3 rounded-sm px-3 py-2.5 text-left text-sm hover:bg-muted"><Download className="h-4 w-4 text-primary" /><span><span className="block font-medium">Download HTML</span><span className="block text-xs text-muted-foreground">Generated assessment file</span></span></button>
                <button role="menuitem" type="button" onClick={() => void handleViewReport()} className="flex w-full items-center gap-3 rounded-sm px-3 py-2.5 text-left text-sm hover:bg-muted"><Eye className="h-4 w-4 text-blue-300" /><span><span className="block font-medium">View Report</span><span className="block text-xs text-muted-foreground">Open the report viewer</span></span></button>
                {!report && <button role="menuitem" type="button" onClick={() => void handleGenerateReport()} className="flex w-full items-center gap-3 rounded-sm px-3 py-2.5 text-left text-sm hover:bg-muted"><FileText className="h-4 w-4 text-amber-300" /><span><span className="block font-medium">Generate Only</span><span className="block text-xs text-muted-foreground">Create without downloading</span></span></button>}
              </div>
            )}
          </div>
        </div>

        {activeTab === 'findings' && (
          <SectionCard title="Findings" subtitle="Summary, evidence, impact, remediation, and retest status for detected issues.">
            {findings.length > 0 ? (
              <div className="space-y-4">
                {findings.map(finding => (
                  <div key={finding.id} className="space-y-3">
                    <FindingCard finding={finding} />
                    <div className="grid gap-3 rounded-lg border border-border bg-background/50 p-4 text-sm lg:grid-cols-2">
                      <DetailBlock title="OWASP Mapping" text={`${finding.category} - safe passive assessment mapping`} />
                      <DetailBlock title="Status / Retest" text="Open in backend data. Retest after remediation is applied." />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No findings yet" description={selectedScan.status === 'completed' ? 'No vulnerabilities were found in this scan.' : 'Scan results are still processing.'} />
            )}
          </SectionCard>
        )}

        {activeTab === 'crawlMap' && (
          <SectionCard title="Crawl Map" subtitle="Pages observed during the safe scan crawl.">
            {crawlNodes.length > 0 ? (
              <div className="space-y-6">
                <CrawlGraph nodes={crawlNodes} />
                <div className="border-t border-border pt-5">
                  <h3 className="mb-3 text-sm font-semibold">Crawl Records</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[760px] text-left text-sm">
                      <thead className="border-b border-border text-xs font-semibold text-muted-foreground">
                        <tr><th className="py-3 pr-4">Path</th><th className="py-3 pr-4">Status</th><th className="py-3 pr-4">Depth</th><th className="py-3 pr-4">Forms</th><th className="py-3 pr-4">Login Input</th><th className="py-3">Findings</th></tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {[...crawlNodes].sort((a, b) => a.depth - b.depth).map(node => (
                          <tr key={node.id} className="hover:bg-muted/30">
                            <td className="py-4 pr-4 break-all font-mono text-xs">{node.path}</td>
                            <td className="py-4 pr-4"><StatusBadge status={node.status_code === 200 ? 'passed' : 'failed'} /></td>
                            <td className="py-4 pr-4">Level {node.depth}</td>
                            <td className="py-4 pr-4">{node.has_forms ? 'Yes' : 'No'}</td>
                            <td className="py-4 pr-4">{node.has_password_field ? 'Yes' : 'No'}</td>
                            <td className="py-4 font-semibold">{node.finding_count || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            ) : <EmptyState title="No crawl records" description="No pages were crawled for this scan." />}
          </SectionCard>
        )}

        {activeTab === 'drift' && (
          <SectionCard title="Posture Drift" subtitle="Comparison with the previous scan for the same target.">
            {postureDiff ? (
              <div className="grid gap-4 lg:grid-cols-3">
                <div className="rounded-lg border border-border bg-background/60 p-5 lg:col-span-2">
                  <p className="text-sm text-muted-foreground">Summary</p>
                  <p className="mt-2 text-xl font-semibold">{postureDiff.summary}</p>
                  <p className="mt-2 text-sm text-muted-foreground">Compared with scan #{postureDiff.previous_scan_id}</p>
                </div>
                <div className="space-y-3 rounded-lg border border-border bg-background/60 p-5">
                  <DriftMetric label="Risk delta" value={postureDiff.risk_score_delta.toFixed(1)} danger={postureDiff.risk_score_delta > 0} />
                  <DriftMetric label="Posture delta" value={postureDiff.posture_score_delta.toString()} danger={postureDiff.posture_score_delta < 0} />
                  <DriftMetric label="New findings" value={postureDiff.new_findings_count.toString()} danger={postureDiff.new_findings_count > 0} />
                  <DriftMetric label="Resolved" value={postureDiff.resolved_findings_count.toString()} />
                </div>
              </div>
            ) : <EmptyState title="No drift available" description="This may be the first scan for the selected target." />}
          </SectionCard>
        )}

        {activeTab === 'evidence' && (
          <SectionCard title="Evidence Artifacts" subtitle="Redacted evidence collected during the safe assessment.">
            {evidence.length > 0 ? (
              <div className="grid gap-4 lg:grid-cols-2">
                {evidence.map(item => (
                  <article key={item.id} className="rounded-lg border border-border bg-background/60 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="font-semibold">{item.title}</h3>
                      <span className="rounded-full bg-muted px-2.5 py-1 text-xs font-medium capitalize">{item.artifact_type.replace('_', ' ')}</span>
                    </div>
                    <p className="mt-3 break-all font-mono text-xs text-muted-foreground">{item.related_url}</p>
                    {item.redacted_text && <pre className="mt-4 max-h-72 overflow-auto rounded-md border border-border bg-card p-3 text-xs leading-5 text-muted-foreground">{item.redacted_text}</pre>}
                  </article>
                ))}
              </div>
            ) : <EmptyState title="No evidence captured" description="Evidence artifacts will appear here after supported scans." />}
          </SectionCard>
        )}

        {activeTab === 'policies' && (
          <SectionCard title="Policy Compliance Results" subtitle="Checks mapped to findings from this scan.">
            {policyResults.length > 0 ? (
              <div className="space-y-4">
                {policyResults.map(pack => (
                  <div key={pack.policy_id} className="rounded-lg border border-border bg-background/60 p-4">
                    <h3 className="mb-3 font-semibold">{pack.title}</h3>
                    <div className="space-y-3">
                      {pack.checks.map(check => (
                        <div key={check.check_id} className="flex flex-col gap-3 rounded-md border border-border bg-card/70 p-3 sm:flex-row sm:items-start sm:justify-between">
                          <div>
                            <p className="flex items-center gap-2 text-sm font-medium">{check.status === 'passed' ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <XCircle className="h-4 w-4 text-red-300" />}{check.title}</p>
                            {check.status === 'failed' && <p className="mt-1 text-sm leading-5 text-muted-foreground">Violations: {check.violating_findings.join(', ')}</p>}
                          </div>
                          <StatusBadge status={check.status} />
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : <EmptyState title="No policy results" description="Policy results are generated for completed scans." />}
          </SectionCard>
        )}
      </PageShell>
    );
  }

  return (
    <PageShell>
      <PageHeader
        title="Scans"
        subtitle="Backend scan records, evidence, crawl maps, findings, drift, and policy results."
        actions={<Link to="/scans/new" className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:bg-primary/90"><Play className="h-4 w-4" /> New Scan</Link>}
      />

      {showNewScan && (
        <SectionCard title="Start New Scan" subtitle="Launch a safe scan against an authorized target.">
          <form onSubmit={handleStartScan} className="grid gap-4 lg:grid-cols-[1fr_260px_auto] lg:items-end">
            <label className="space-y-2 text-sm font-medium">Target
              <select required className="h-10 w-full rounded-md border border-input bg-background px-3" value={formData.target_id} onChange={e => setFormData({ ...formData, target_id: e.target.value })}>
                <option value="" disabled>Select a target...</option>
                {targets.map(target => <option key={target.id} value={target.id}>{target.name} ({target.base_url})</option>)}
              </select>
            </label>
            <label className="space-y-2 text-sm font-medium">Scan Profile
              <select className="h-10 w-full rounded-md border border-input bg-background px-3" value={formData.profile} onChange={e => setFormData({ ...formData, profile: e.target.value })}>
                <option value="Passive Scan">Passive Scan</option>
                <option value="Standard Safe Scan">Standard Safe Scan</option>
                <option value="Full Safe Scan">Full Safe Scan</option>
              </select>
            </label>
            <div className="flex gap-3">
              <button type="button" onClick={() => setShowNewScan(false)} className="h-10 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted">Cancel</button>
              <button type="submit" disabled={!formData.target_id} className="h-10 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:bg-primary/90 disabled:opacity-50">Start</button>
            </div>
          </form>
        </SectionCard>
      )}

      {error && <EmptyState title="Scans unavailable" description={error} action={<button onClick={() => void fetchData()} className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Try Again</button>} />}
      {!error && <SectionCard title="Scan Records" subtitle="Status, target, profile, findings, posture, and risk score for each scan.">
        {scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead className="border-b border-border text-xs font-semibold text-muted-foreground">
                <tr><th className="py-3 pr-4">ID</th><th className="py-3 pr-4">Target</th><th className="py-3 pr-4">Profile</th><th className="py-3 pr-4">Started</th><th className="py-3 pr-4">Status</th><th className="py-3 pr-4">Findings</th><th className="py-3 pr-4">Risk</th><th className="py-3 text-right">Action</th></tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map(scan => (
                  <tr key={scan.id} className="hover:bg-muted/30">
                    <td className="py-4 pr-4 font-semibold">#{scan.id}</td>
                    <td className="py-4 pr-4 font-medium">{getTargetName(scan.target_id)}</td>
                    <td className="py-4 pr-4 text-muted-foreground">{scan.profile}</td>
                    <td className="py-4 pr-4 text-muted-foreground">{new Date(scan.started_at).toLocaleString()}</td>
                    <td className="py-4 pr-4"><StatusBadge status={scan.status} /></td>
                    <td className="py-4 pr-4 font-semibold">{scan.status === 'completed' ? scan.total_findings : '-'}</td>
                    <td className="py-4 pr-4">{scan.status === 'completed' ? <RiskScoreBadge score={scan.risk_score} /> : <span className="text-muted-foreground">Not available</span>}</td>
                    <td className="py-4 text-right"><div className="inline-flex items-center gap-1"><button onClick={() => void loadScanDetails(scan)} className="inline-flex items-center gap-1 rounded-md px-3 py-2 text-sm font-semibold text-primary hover:bg-primary/10">View Details <ChevronRight className="h-4 w-4" /></button><button onClick={event => void removeScan(event, scan)} disabled={scan.status === 'queued' || scan.status === 'running'} title="Delete scan" className="rounded-md p-2 text-muted-foreground hover:bg-red-500/10 hover:text-red-300 disabled:cursor-not-allowed disabled:opacity-30"><Trash2 className="h-4 w-4" /></button></div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : !loading && <EmptyState title="No scans yet" description="Start a safe scan to populate this table." action={<Link to="/scans/new" className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Start Scan</Link>} />}
      </SectionCard>}
    </PageShell>
  );
}

function PostureMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-background/60 p-4">
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className="mt-2 text-2xl font-semibold">{value}<span className="text-sm text-muted-foreground">/100</span></p>
    </div>
  );
}

function TabButton({ active, onClick, icon, children }: { active: boolean; onClick: () => void; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <button onClick={onClick} className={`inline-flex items-center gap-2 border-b-2 py-3 text-sm font-semibold transition-colors ${active ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
      {icon}{children}
    </button>
  );
}

function DetailBlock({ title, text }: { title: string; text: string }) {
  return (
    <div>
      <p className="font-semibold">{title}</p>
      <p className="mt-1 leading-6 text-muted-foreground">{text}</p>
    </div>
  );
}

function DriftMetric({ label, value, danger = false }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="flex items-center justify-between border-b border-border pb-2 last:border-0 last:pb-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className={danger ? 'font-semibold text-red-300' : 'font-semibold text-foreground'}>{value}</span>
    </div>
  );
}

const GRAPH_NODE_WIDTH = 196;
const GRAPH_NODE_HEIGHT = 86;
const GRAPH_COLUMN_GAP = 92;
const GRAPH_ROW_GAP = 34;

function CrawlGraph({ nodes }: { nodes: CrawlNode[] }) {
  const [zoom, setZoom] = useState(1);
  const [selectedId, setSelectedId] = useState<number>(nodes[0].id);
  const layout = useMemo(() => buildCrawlLayout(nodes), [nodes]);
  const selectedNode = nodes.find(node => node.id === selectedId) || nodes[0];
  const markerId = `crawl-arrow-${nodes[0].scan_id}`;

  const selectNode = (nodeId: number) => setSelectedId(nodeId);

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background/50">
      <div className="flex flex-col gap-3 border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted-foreground">
          <GraphLegend color="#34d399" label="Page" />
          <GraphLegend color="#60a5fa" label="Form" />
          <GraphLegend color="#f87171" label="Login input" />
          <GraphLegend color="#fbbf24" label="Findings" />
        </div>
        <div className="flex items-center gap-1">
          <button type="button" title="Zoom out" aria-label="Zoom out" onClick={() => setZoom(value => Math.max(0.7, Number((value - 0.1).toFixed(1))))} disabled={zoom <= 0.7} className="inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-30"><ZoomOut className="h-4 w-4" /></button>
          <span className="w-12 text-center text-xs font-semibold text-muted-foreground">{Math.round(zoom * 100)}%</span>
          <button type="button" title="Zoom in" aria-label="Zoom in" onClick={() => setZoom(value => Math.min(1.4, Number((value + 0.1).toFixed(1))))} disabled={zoom >= 1.4} className="inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-30"><ZoomIn className="h-4 w-4" /></button>
          <button type="button" title="Reset zoom" aria-label="Reset zoom" onClick={() => setZoom(1)} className="inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"><Maximize2 className="h-4 w-4" /></button>
        </div>
      </div>

      <div className="max-h-[520px] overflow-auto">
        <svg
          width={layout.width * zoom}
          height={layout.height * zoom}
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          role="img"
          aria-label={`Crawl graph with ${nodes.length} pages across ${layout.depthCount} depth levels`}
          className="block"
        >
          <defs>
            <marker id={markerId} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L8,4 L0,8 Z" fill="hsl(var(--muted-foreground))" />
            </marker>
          </defs>

          {Array.from({ length: layout.depthCount }, (_, depth) => (
            <text key={depth} x={layout.left + depth * (GRAPH_NODE_WIDTH + GRAPH_COLUMN_GAP)} y="24" fill="hsl(var(--muted-foreground))" fontSize="11" fontWeight="600">DEPTH {depth}</text>
          ))}

          {layout.edges.map(edge => (
            <path key={`${edge.from.id}-${edge.to.id}`} d={edge.path} fill="none" stroke="hsl(var(--muted-foreground))" strokeWidth="1.5" opacity="0.45" markerEnd={`url(#${markerId})`} />
          ))}

          {layout.nodes.map(({ node, x, y }) => {
            const tone = crawlNodeTone(node);
            const selected = node.id === selectedNode.id;
            return (
              <g key={node.id} transform={`translate(${x} ${y})`} role="button" tabIndex={0} aria-label={`${node.path}, depth ${node.depth}, ${node.finding_count} findings`} onClick={() => selectNode(node.id)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') selectNode(node.id); }} className="cursor-pointer outline-none">
                <title>{node.url}</title>
                <rect width={GRAPH_NODE_WIDTH} height={GRAPH_NODE_HEIGHT} rx="6" fill="hsl(var(--card))" stroke={selected ? 'hsl(var(--primary))' : tone} strokeWidth={selected ? 3 : 1.5} />
                <circle cx="16" cy="19" r="5" fill={tone} />
                <text x="28" y="23" fill="hsl(var(--foreground))" fontSize="13" fontWeight="600">{crawlNodeLabel(node.path)}</text>
                <text x="14" y="44" fill="hsl(var(--muted-foreground))" fontSize="10">{node.status_code ? `HTTP ${node.status_code}` : 'NO RESPONSE'} - {node.content_type?.split(';')[0] || 'unknown type'}</text>
                <text x="14" y="67" fill="hsl(var(--muted-foreground))" fontSize="10">{node.has_forms ? 'FORM' : 'PAGE'}{node.has_password_field ? ' - LOGIN INPUT' : ''}</text>
                {node.finding_count > 0 && <g><rect x="145" y="55" width="38" height="20" rx="6" fill="#fbbf24" opacity="0.18" /><text x="164" y="69" textAnchor="middle" fill="#fbbf24" fontSize="10" fontWeight="700">{node.finding_count} ISS</text></g>}
              </g>
            );
          })}
        </svg>
      </div>

      <div className="grid gap-4 border-t border-border p-4 text-sm sm:grid-cols-[1fr_auto] sm:items-start">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold">{selectedNode.page_title || selectedNode.path}</h3><StatusBadge status={selectedNode.status_code && selectedNode.status_code < 400 ? 'passed' : 'failed'} /></div>
          <p className="mt-2 break-all font-mono text-xs text-muted-foreground">{selectedNode.url}</p>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs text-muted-foreground"><span>Depth {selectedNode.depth}</span><span>{selectedNode.finding_count} findings</span><span>{selectedNode.has_forms ? 'Form detected' : 'No forms'}</span><span>{selectedNode.has_password_field ? 'Login input detected' : 'No login input'}</span></div>
        </div>
        <a href={selectedNode.url} target="_blank" rel="noreferrer" title="Open crawled page" className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border text-muted-foreground hover:bg-muted hover:text-foreground"><ExternalLink className="h-4 w-4" /></a>
      </div>
    </div>
  );
}

function GraphLegend({ color, label }: { color: string; label: string }) {
  return <span className="inline-flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} />{label}</span>;
}

function crawlNodeTone(node: CrawlNode) {
  if (!node.status_code || node.status_code >= 400) return '#f87171';
  if (node.has_password_field) return '#f87171';
  if (node.finding_count > 0) return '#fbbf24';
  if (node.has_forms) return '#60a5fa';
  return '#34d399';
}

function crawlNodeLabel(path: string) {
  if (path.length <= 23) return path;
  return `${path.slice(0, 20)}...`;
}

function buildCrawlLayout(nodes: CrawlNode[]) {
  const left = 46;
  const top = 48;
  const grouped = new Map<number, CrawlNode[]>();
  nodes.forEach(node => grouped.set(node.depth, [...(grouped.get(node.depth) || []), node]));
  grouped.forEach(group => group.sort((a, b) => a.path.localeCompare(b.path)));
  const maxDepth = Math.max(...nodes.map(node => node.depth));
  const maxRows = Math.max(...Array.from(grouped.values()).map(group => group.length));
  const width = Math.max(760, left * 2 + (maxDepth + 1) * GRAPH_NODE_WIDTH + maxDepth * GRAPH_COLUMN_GAP);
  const height = Math.max(280, top + maxRows * GRAPH_NODE_HEIGHT + Math.max(0, maxRows - 1) * GRAPH_ROW_GAP + 36);
  const positioned = nodes.map(node => {
    const group = grouped.get(node.depth) || [];
    const row = group.findIndex(item => item.id === node.id);
    const groupHeight = group.length * GRAPH_NODE_HEIGHT + Math.max(0, group.length - 1) * GRAPH_ROW_GAP;
    return {
      node,
      x: left + node.depth * (GRAPH_NODE_WIDTH + GRAPH_COLUMN_GAP),
      y: top + (height - top - 36 - groupHeight) / 2 + row * (GRAPH_NODE_HEIGHT + GRAPH_ROW_GAP),
    };
  });
  const byUrl = new Map(positioned.map(item => [item.node.url, item]));
  const edges = positioned.flatMap(to => {
    const from = to.node.parent_url ? byUrl.get(to.node.parent_url) : undefined;
    if (!from) return [];
    const startX = from.x + GRAPH_NODE_WIDTH;
    const startY = from.y + GRAPH_NODE_HEIGHT / 2;
    const endX = to.x - 8;
    const endY = to.y + GRAPH_NODE_HEIGHT / 2;
    const control = Math.max(34, (endX - startX) / 2);
    return [{ from: from.node, to: to.node, path: `M ${startX} ${startY} C ${startX + control} ${startY}, ${endX - control} ${endY}, ${endX} ${endY}` }];
  });
  return { nodes: positioned, edges, width, height, left, depthCount: maxDepth + 1 };
}
