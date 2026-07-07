import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, ArrowLeft, Camera, CheckCircle2, ChevronRight, FileText, GitMerge, Play, ShieldCheck, XCircle } from 'lucide-react';
import type { CrawlNode, EvidenceArtifact, Finding, PostureDiff, Scan, Target } from '../types';
import { getPolicyResults, getPostureDiff, getTargets, listCrawlNodes, listEvidence, listFindings, listScans, startDemoScan } from '../data/demoData';
import { EmptyState, FindingCard, PageHeader, PageShell, RiskScoreBadge, SectionCard, StatCard, StatusBadge } from '../components/ui';

type Tab = 'findings' | 'crawlMap' | 'drift' | 'evidence' | 'policies';

export function Scans() {
  const [searchParams] = useSearchParams();
  const initialTargetId = searchParams.get('targetId');
  const highlightScanId = searchParams.get('highlight');
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNewScan, setShowNewScan] = useState(!!initialTargetId);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [crawlNodes, setCrawlNodes] = useState<CrawlNode[]>([]);
  const [postureDiff, setPostureDiff] = useState<PostureDiff | null>(null);
  const [evidence, setEvidence] = useState<EvidenceArtifact[]>([]);
  const [policyResults, setPolicyResults] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>('findings');
  const [formData, setFormData] = useState({ target_id: initialTargetId || '', profile: 'Standard Safe Scan' });

  const fetchData = () => {
    setScans(listScans());
    setTargets(getTargets());
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (!highlightScanId || scans.length === 0) return;
    const scan = scans.find(item => item.id.toString() === highlightScanId);
    if (scan) loadScanDetails(scan);
  }, [highlightScanId, scans]);

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    startDemoScan(Number(formData.target_id), formData.profile);
    setShowNewScan(false);
    fetchData();
  };

  const loadScanDetails = (scan: Scan) => {
    setSelectedScan(scan);
    setActiveTab('findings');
    setFindings(listFindings(scan.id));
    setCrawlNodes(listCrawlNodes(scan.id));
    setEvidence(listEvidence(scan.id));
    setPolicyResults(getPolicyResults(scan.id));
    setPostureDiff(getPostureDiff(scan.id));
  };

  const getTargetName = (id: number) => targets.find(target => target.id === id)?.name || `Target #${id}`;

  if (selectedScan) {
    return (
      <PageShell>
        <button onClick={() => setSelectedScan(null)} className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" /> Back to Scans
        </button>

        <PageHeader
          title={`Scan Details #${selectedScan.id}`}
          subtitle={`${getTargetName(selectedScan.target_id)} · ${selectedScan.profile} · Demo data`}
          actions={<StatusBadge status={selectedScan.status} />}
        />

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Posture Score" value={<>{selectedScan.overall_posture_score}<span className="text-base text-muted-foreground">/100</span></>} tone="good" icon={<ShieldCheck className="h-5 w-5" />} />
          <StatCard label="Risk Score" value={<>{selectedScan.risk_score.toFixed(1)}<span className="text-base text-muted-foreground">/10</span></>} tone={selectedScan.risk_score >= 6 ? 'danger' : 'warn'} icon={<Activity className="h-5 w-5" />} />
          <StatCard label="Findings" value={selectedScan.total_findings} tone="warn" icon={<FileText className="h-5 w-5" />} />
          <div className="rounded-lg border border-border bg-card/90 p-5">
            <p className="text-sm font-medium text-muted-foreground">Report</p>
            <p className="mt-4 text-sm leading-6 text-muted-foreground">Demo report is available from the Reports page.</p>
            <Link to="/reports" className="mt-4 inline-flex h-10 items-center gap-2 rounded-md border border-border px-4 text-sm font-semibold hover:bg-muted">View Reports <ChevronRight className="h-4 w-4" /></Link>
          </div>
        </div>

        <SectionCard title="Security Posture Breakdown" subtitle="Category scores captured by the selected scan.">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <PostureMetric label="Transport" value={selectedScan.posture_transport_security} />
            <PostureMetric label="Browser" value={selectedScan.posture_browser_defense} />
            <PostureMetric label="Session" value={selectedScan.posture_session_safety} />
            <PostureMetric label="Exposure" value={selectedScan.posture_exposure_hygiene} />
            <PostureMetric label="Auth Surface" value={selectedScan.posture_authentication_surface} />
          </div>
        </SectionCard>

        <div className="overflow-x-auto border-b border-border">
          <nav className="flex min-w-max gap-6">
            <TabButton active={activeTab === 'findings'} onClick={() => setActiveTab('findings')}>Findings</TabButton>
            <TabButton active={activeTab === 'crawlMap'} onClick={() => setActiveTab('crawlMap')} icon={<GitMerge className="h-4 w-4" />}>Crawl Map</TabButton>
            <TabButton active={activeTab === 'drift'} onClick={() => setActiveTab('drift')}>Posture Drift</TabButton>
            <TabButton active={activeTab === 'evidence'} onClick={() => setActiveTab('evidence')} icon={<Camera className="h-4 w-4" />}>Evidence</TabButton>
            <TabButton active={activeTab === 'policies'} onClick={() => setActiveTab('policies')} icon={<ShieldCheck className="h-4 w-4" />}>Policy Results</TabButton>
          </nav>
        </div>

        {activeTab === 'findings' && (
          <SectionCard title="Findings" subtitle="Summary, evidence, impact, remediation, and retest status for detected issues.">
            {findings.length > 0 ? (
              <div className="space-y-4">
                {findings.map(finding => (
                  <div key={finding.id} className="space-y-3">
                    <FindingCard finding={finding} />
                    <div className="grid gap-3 rounded-lg border border-border bg-background/50 p-4 text-sm lg:grid-cols-2">
                      <DetailBlock title="OWASP Mapping" text={`${finding.category} · safe passive assessment mapping`} />
                      <DetailBlock title="Status / Retest" text="Open in demo data. Retest after remediation is applied." />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No findings yet" description={selectedScan.status === 'completed' ? 'No vulnerabilities were found in this demo scan.' : 'Scan results are still processing.'} />
            )}
          </SectionCard>
        )}

        {activeTab === 'crawlMap' && (
          <SectionCard title="Crawl Map" subtitle="Pages observed during the safe scan crawl.">
            {crawlNodes.length > 0 ? (
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
                      {pack.checks.map((check: any) => (
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
            ) : <EmptyState title="No policy results" description="Policy results are generated for completed demo scans." />}
          </SectionCard>
        )}
      </PageShell>
    );
  }

  return (
    <PageShell>
      <PageHeader
        title="Scans"
        subtitle="Demo data. Review scan records, inspect evidence, and open findings without leaving the scan workflow."
        actions={<Link to="/scans/new" className="inline-flex h-10 items-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:bg-primary/90"><Play className="h-4 w-4" /> New Scan</Link>}
      />

      {showNewScan && (
        <SectionCard title="Start New Scan" subtitle="Launch a safe demo scan against an authorized target.">
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

      <SectionCard title="Scan Records" subtitle="Status, target, profile, findings, posture, and risk score for each scan.">
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
                    <td className="py-4 pr-4 font-semibold">{scan.total_findings}</td>
                    <td className="py-4 pr-4"><RiskScoreBadge score={scan.risk_score} /></td>
                    <td className="py-4 text-right"><button onClick={() => loadScanDetails(scan)} className="inline-flex items-center gap-1 rounded-md px-3 py-2 text-sm font-semibold text-primary hover:bg-primary/10">View Details <ChevronRight className="h-4 w-4" /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : !loading && <EmptyState title="No scans yet" description="Start a safe scan to populate this table." action={<Link to="/scans/new" className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Start Scan</Link>} />}
      </SectionCard>
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
