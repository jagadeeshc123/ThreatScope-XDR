import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import type { Scan, Target, Finding, CrawlNode, PostureDiff, EvidenceArtifact } from '../types';
import { Play, Activity, ChevronRight, AlertTriangle, ShieldAlert, GitMerge, TrendingUp, TrendingDown, Minus, Camera, ShieldCheck, CheckCircle2, XCircle } from 'lucide-react';
import { useSearchParams, Link } from 'react-router-dom';

export function Scans() {
  const [searchParams] = useSearchParams();
  const initialTargetId = searchParams.get('targetId');
  
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
  const [activeTab, setActiveTab] = useState<'findings' | 'crawlMap' | 'drift' | 'evidence' | 'policies'>('findings');
  
  const [formData, setFormData] = useState({
    target_id: initialTargetId || '',
    profile: 'Standard Safe Scan'
  });

  const fetchData = async () => {
    try {
      const [scansRes, targetsRes] = await Promise.all([
        apiClient.get<Scan[]>('/scans'),
        apiClient.get<Target[]>('/targets')
      ]);
      setScans(scansRes.data);
      setTargets(targetsRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiClient.post('/scans/start', formData);
      setShowNewScan(false);
      fetchData();
    } catch (err) {
      console.error(err);
      alert('Failed to start scan');
    }
  };

  const loadScanDetails = async (scan: Scan) => {
    setSelectedScan(scan);
    setActiveTab('findings');
    setPostureDiff(null);
    try {
      const [findingsRes, crawlRes, evidenceRes, policiesRes] = await Promise.all([
        apiClient.get<Finding[]>(`/scans/${scan.id}/findings`),
        apiClient.get<CrawlNode[]>(`/scans/${scan.id}/crawl-map`),
        apiClient.get<EvidenceArtifact[]>(`/scans/${scan.id}/evidence`),
        apiClient.get<any[]>(`/scans/${scan.id}/policy-results`)
      ]);
      setFindings(findingsRes.data);
      setCrawlNodes(crawlRes.data);
      setEvidence(evidenceRes.data);
      setPolicyResults(policiesRes.data);
      
      try {
        const diffRes = await apiClient.get<PostureDiff>(`/scans/${scan.id}/diff`);
        setPostureDiff(diffRes.data);
      } catch (e) {
        // May not exist if it's the first scan
        console.log("No posture diff found for this scan");
      }
    } catch (err) {
      console.error(err);
    }
  };

  const getTargetName = (id: number) => targets.find(t => t.id === id)?.name || `Target #${id}`;

  const getSeverityColor = (sev: string) => {
    switch(sev) {
      case 'critical': return 'bg-red-500/20 text-red-500 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-500 border-orange-500/50';
      case 'medium': return 'bg-amber-500/20 text-amber-500 border-amber-500/50';
      case 'low': return 'bg-blue-500/20 text-blue-500 border-blue-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  if (selectedScan) {
    return (
      <div className="p-8 space-y-6">
        <button onClick={() => setSelectedScan(null)} className="text-muted-foreground hover:text-foreground text-sm flex items-center mb-4">
          ← Back to Scans
        </button>
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold tracking-tight mb-2">Scan Details #{selectedScan.id}</h1>
            <p className="text-muted-foreground">Target: {getTargetName(selectedScan.target_id)} | Profile: {selectedScan.profile}</p>
          </div>
          <div className="text-right">
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-bold uppercase ${selectedScan.status === 'completed' ? 'bg-primary/20 text-primary' : 'bg-muted text-muted-foreground'}`}>
              {selectedScan.status === 'running' && <Activity className="w-4 h-4 mr-2 animate-pulse" />}
              {selectedScan.status}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-card border border-border p-6 rounded-xl">
            <p className="text-sm text-muted-foreground mb-1">Posture Score</p>
            <p className="text-4xl font-bold text-primary">{selectedScan.overall_posture_score} <span className="text-sm text-muted-foreground font-normal">/ 100</span></p>
          </div>
          <div className="bg-card border border-border p-6 rounded-xl">
            <p className="text-sm text-muted-foreground mb-1">Risk Score</p>
            <p className="text-4xl font-bold">{selectedScan.risk_score.toFixed(1)} <span className="text-sm text-muted-foreground font-normal">/ 10</span></p>
          </div>
          <div className="bg-card border border-border p-6 rounded-xl">
            <p className="text-sm text-muted-foreground mb-1">Total Findings</p>
            <p className="text-4xl font-bold">{selectedScan.total_findings}</p>
          </div>
          <div className="bg-card border border-border p-6 rounded-xl flex flex-col justify-center">
            <button 
              onClick={async () => {
                try {
                  await apiClient.post(`/reports/generate/${selectedScan.id}`);
                  alert('Report generated! Check the Reports page.');
                } catch(e) { console.error(e); }
              }}
              className="bg-secondary text-secondary-foreground hover:bg-secondary/80 py-2 rounded-md font-medium"
            >
              Generate Report
            </button>
          </div>
        </div>

        <div className="bg-card border border-border p-6 rounded-xl">
          <h2 className="text-lg font-bold mb-4">Security Posture Breakdown</h2>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-center">
            <div className="p-4 bg-background rounded-lg border border-border">
              <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wider">Transport</p>
              <p className="text-2xl font-bold">{selectedScan.posture_transport_security}</p>
            </div>
            <div className="p-4 bg-background rounded-lg border border-border">
              <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wider">Browser</p>
              <p className="text-2xl font-bold">{selectedScan.posture_browser_defense}</p>
            </div>
            <div className="p-4 bg-background rounded-lg border border-border">
              <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wider">Session</p>
              <p className="text-2xl font-bold">{selectedScan.posture_session_safety}</p>
            </div>
            <div className="p-4 bg-background rounded-lg border border-border">
              <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wider">Exposure</p>
              <p className="text-2xl font-bold">{selectedScan.posture_exposure_hygiene}</p>
            </div>
            <div className="p-4 bg-background rounded-lg border border-border">
              <p className="text-xs text-muted-foreground mb-1 uppercase tracking-wider">Auth</p>
              <p className="text-2xl font-bold">{selectedScan.posture_authentication_surface}</p>
            </div>
          </div>
        </div>

        <div className="mt-8 border-b border-border">
          <nav className="flex space-x-8">
            <button
              onClick={() => setActiveTab('findings')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'findings' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              Vulnerability Findings
            </button>
            <button
              onClick={() => setActiveTab('crawlMap')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors flex items-center ${
                activeTab === 'crawlMap' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              <GitMerge className="w-4 h-4 mr-2" /> Crawl Map
            </button>
            <button
              onClick={() => setActiveTab('drift')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors flex items-center ${
                activeTab === 'drift' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              Posture Drift
            </button>
            <button
              onClick={() => setActiveTab('evidence')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors flex items-center ${
                activeTab === 'evidence' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              <Camera className="w-4 h-4 mr-2" /> Evidence
            </button>
            <button
              onClick={() => setActiveTab('policies')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors flex items-center ${
                activeTab === 'policies' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              <ShieldCheck className="w-4 h-4 mr-2" /> Policy Results
            </button>
          </nav>
        </div>

        <div className="mt-6">
          {activeTab === 'findings' && (
            <div>
              <h2 className="text-xl font-bold mb-4">Findings</h2>
              {findings.length > 0 ? (
                <div className="space-y-4">
                  {findings.map(f => (
                    <div key={f.id} className="bg-card border border-border p-5 rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-bold text-lg flex items-center">
                          <span className={`border px-2 py-0.5 rounded text-xs uppercase mr-3 ${getSeverityColor(f.severity)}`}>
                            {f.severity}
                          </span>
                          {f.title}
                        </h3>
                        <span className="text-sm text-muted-foreground">{f.category}</span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-3 font-mono bg-muted/50 p-2 rounded">{f.affected_url}</p>
                      <p className="text-sm mb-4">{f.description}</p>
                      
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm mt-4">
                        <div className="bg-background/50 p-4 rounded border border-border">
                          <p className="font-bold mb-2 flex items-center text-destructive"><AlertTriangle className="w-4 h-4 mr-2"/> Impact</p>
                          <p className="text-muted-foreground">{f.impact}</p>
                        </div>
                        <div className="bg-background/50 p-4 rounded border border-border">
                          <p className="font-bold mb-2 flex items-center text-primary"><ShieldAlert className="w-4 h-4 mr-2"/> Remediation</p>
                          <p className="text-muted-foreground">{f.remediation}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-muted-foreground p-8 text-center bg-card rounded-lg border border-border">
                  {selectedScan.status === 'completed' ? 'No vulnerabilities found.' : 'Scan is still processing...'}
                </div>
              )}
            </div>
          )}

          {activeTab === 'crawlMap' && (
            <div>
              <h2 className="text-xl font-bold mb-4">Crawl Map</h2>
              {crawlNodes.length > 0 ? (
                <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
                  <table className="w-full text-sm text-left">
                    <thead className="bg-muted text-muted-foreground text-xs uppercase font-semibold">
                      <tr>
                        <th className="px-4 py-3">Path</th>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Depth</th>
                        <th className="px-4 py-3">Forms</th>
                        <th className="px-4 py-3">Login Input</th>
                        <th className="px-4 py-3">Findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {crawlNodes.sort((a, b) => a.depth - b.depth).map(node => (
                        <tr key={node.id} className="border-b border-border hover:bg-muted/50 transition-colors">
                          <td className="px-4 py-3 font-mono text-xs">{node.path}</td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-1 rounded text-xs font-bold ${node.status_code === 200 ? 'bg-green-500/20 text-green-500' : 'bg-muted text-muted-foreground'}`}>
                              {node.status_code || '-'}
                            </span>
                          </td>
                          <td className="px-4 py-3">Level {node.depth}</td>
                          <td className="px-4 py-3">{node.has_forms ? 'Yes' : 'No'}</td>
                          <td className="px-4 py-3 text-destructive font-medium">{node.has_password_field ? 'Yes' : 'No'}</td>
                          <td className="px-4 py-3">
                            {node.finding_count > 0 ? (
                              <span className="bg-destructive/20 text-destructive px-2 py-1 rounded font-bold">{node.finding_count}</span>
                            ) : '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-muted-foreground p-8 text-center bg-card rounded-lg border border-border">
                  {selectedScan.status === 'completed' ? 'No pages crawled.' : 'Scan is still processing...'}
                </div>
              )}
            </div>
          )}

          {activeTab === 'drift' && (
            <div>
              <h2 className="text-xl font-bold mb-4">Posture Drift</h2>
              {postureDiff ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-card border border-border p-6 rounded-xl flex flex-col items-center justify-center text-center">
                    <p className="text-sm text-muted-foreground mb-2">Summary</p>
                    <div className="flex items-center mb-2">
                      {postureDiff.risk_score_delta > 0 ? (
                        <TrendingUp className="w-8 h-8 text-destructive mr-2" />
                      ) : postureDiff.risk_score_delta < 0 ? (
                        <TrendingDown className="w-8 h-8 text-green-500 mr-2" />
                      ) : (
                        <Minus className="w-8 h-8 text-muted-foreground mr-2" />
                      )}
                      <span className="text-2xl font-bold">{postureDiff.summary}</span>
                    </div>
                    <p className="text-muted-foreground text-sm">Compared to previous scan #{postureDiff.previous_scan_id}</p>
                    <p className="mt-4 font-bold">
                      Risk Score Change: <span className={postureDiff.risk_score_delta > 0 ? 'text-destructive' : postureDiff.risk_score_delta < 0 ? 'text-green-500' : ''}>
                        {postureDiff.risk_score_delta > 0 ? '+' : ''}{postureDiff.risk_score_delta.toFixed(1)}
                      </span>
                    </p>
                    <p className="mt-1 font-bold">
                      Posture Score Change: <span className={postureDiff.posture_score_delta < 0 ? 'text-destructive' : postureDiff.posture_score_delta > 0 ? 'text-green-500' : ''}>
                        {postureDiff.posture_score_delta > 0 ? '+' : ''}{postureDiff.posture_score_delta}
                      </span>
                    </p>
                  </div>
                  
                  <div className="bg-card border border-border p-6 rounded-xl flex flex-col justify-center space-y-4">
                    <div className="flex justify-between items-center border-b border-border pb-2">
                      <span className="font-medium text-muted-foreground">New Findings</span>
                      <span className="font-bold text-destructive">{postureDiff.new_findings_count}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-border pb-2">
                      <span className="font-medium text-muted-foreground">Resolved Findings</span>
                      <span className="font-bold text-green-500">{postureDiff.resolved_findings_count}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="font-medium text-muted-foreground">Unchanged Findings</span>
                      <span className="font-bold">{postureDiff.unchanged_findings_count}</span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-muted-foreground p-8 text-center bg-card rounded-lg border border-border">
                  {selectedScan.status === 'completed' ? 'No posture drift available (this may be the first scan for this target).' : 'Scan is still processing...'}
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div>
              <h2 className="text-xl font-bold mb-4">Evidence Artifacts</h2>
              {evidence.length > 0 ? (
                <div className="space-y-4">
                  {evidence.map(ev => (
                    <div key={ev.id} className="bg-card border border-border p-5 rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-bold text-lg flex items-center">
                          <Camera className="w-5 h-5 mr-3 text-muted-foreground"/>
                          {ev.title}
                        </h3>
                        <span className="text-sm text-muted-foreground bg-secondary/30 px-2 py-1 rounded capitalize">{ev.artifact_type.replace('_', ' ')}</span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-3 font-mono bg-muted/50 p-2 rounded">{ev.related_url}</p>
                      
                      {ev.redacted_text && (
                        <div className="mt-4 bg-background/50 border border-border p-4 rounded-md overflow-x-auto max-h-96 overflow-y-auto">
                          <pre className="text-xs font-mono whitespace-pre-wrap">{ev.redacted_text}</pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-muted-foreground p-8 text-center bg-card rounded-lg border border-border">
                  {selectedScan.status === 'completed' ? 'No evidence artifacts captured.' : 'Scan is still processing...'}
                </div>
              )}
            </div>
          )}

          {activeTab === 'policies' && (
            <div>
              <h2 className="text-xl font-bold mb-4">Policy Compliance Results</h2>
              {policyResults.length > 0 ? (
                <div className="space-y-6">
                  {policyResults.map(pack => (
                    <div key={pack.policy_id} className="bg-card border border-border p-6 rounded-xl">
                      <h3 className="font-bold text-lg mb-4 flex items-center">
                        <ShieldCheck className="w-5 h-5 mr-2 text-primary" /> {pack.title}
                      </h3>
                      <div className="space-y-3">
                        {pack.checks.map((check: any) => (
                          <div key={check.check_id} className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-background border border-border rounded-lg">
                            <div className="mb-2 md:mb-0">
                              <p className="font-medium flex items-center">
                                {check.status === 'passed' ? (
                                  <CheckCircle2 className="w-4 h-4 text-green-500 mr-2" />
                                ) : (
                                  <XCircle className="w-4 h-4 text-destructive mr-2" />
                                )}
                                {check.title}
                              </p>
                              {check.status === 'failed' && (
                                <p className="text-xs text-muted-foreground mt-1 ml-6">Violations: {check.violating_findings.join(', ')}</p>
                              )}
                            </div>
                            <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${check.status === 'passed' ? 'bg-green-500/20 text-green-500' : 'bg-destructive/20 text-destructive'}`}>
                              {check.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-muted-foreground p-8 text-center bg-card rounded-lg border border-border">
                  {selectedScan.status === 'completed' ? 'No policy results available.' : 'Scan is still processing...'}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold tracking-tight">Scans</h1>
        <Link to="/scans/new" className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center">
          <Play className="w-4 h-4 mr-2" />
          New Scan
        </Link>
      </div>

      {showNewScan && (
        <div className="bg-card border border-border rounded-xl p-6 shadow-sm max-w-2xl">
          <h2 className="text-xl font-bold mb-4">Start New Scan</h2>
          <form onSubmit={handleStartScan} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Target</label>
              <select required className="w-full bg-background border border-input rounded-md px-3 py-2" value={formData.target_id} onChange={e => setFormData({...formData, target_id: e.target.value})}>
                <option value="" disabled>Select a target...</option>
                {targets.map(t => (
                  <option key={t.id} value={t.id}>{t.name} ({t.base_url})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Scan Profile</label>
              <select className="w-full bg-background border border-input rounded-md px-3 py-2" value={formData.profile} onChange={e => setFormData({...formData, profile: e.target.value})}>
                <option value="Passive Scan">Passive Scan</option>
                <option value="Standard Safe Scan">Standard Safe Scan</option>
                <option value="Full Safe Scan">Full Safe Scan</option>
              </select>
              <p className="text-xs text-muted-foreground mt-2">All profiles use safe, non-destructive reconnaissance methods.</p>
            </div>
            <div className="flex justify-end space-x-3 pt-4">
              <button type="button" onClick={() => setShowNewScan(false)} className="px-4 py-2 border border-border rounded-md hover:bg-muted">Cancel</button>
              <button type="submit" disabled={!formData.target_id} className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50">Start Scan</button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
        <table className="w-full text-sm text-left">
          <thead className="bg-muted text-muted-foreground text-xs uppercase font-semibold">
            <tr>
              <th className="px-6 py-4">ID</th>
              <th className="px-6 py-4">Target</th>
              <th className="px-6 py-4">Profile</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Risk Score</th>
              <th className="px-6 py-4">Findings</th>
              <th className="px-6 py-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <tr key={scan.id} className="border-b border-border hover:bg-muted/50 transition-colors">
                <td className="px-6 py-4">#{scan.id}</td>
                <td className="px-6 py-4 font-medium">{getTargetName(scan.target_id)}</td>
                <td className="px-6 py-4">{scan.profile}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium uppercase ${scan.status === 'completed' ? 'bg-primary/20 text-primary' : 'bg-secondary text-secondary-foreground'}`}>
                    {scan.status}
                  </span>
                </td>
                <td className="px-6 py-4 font-bold">{scan.risk_score.toFixed(1)}</td>
                <td className="px-6 py-4">{scan.total_findings}</td>
                <td className="px-6 py-4 text-right">
                  <button onClick={() => loadScanDetails(scan)} className="text-primary hover:underline flex items-center justify-end w-full">
                    View Details <ChevronRight className="w-4 h-4 ml-1"/>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && scans.length === 0 && (
          <div className="p-12 text-center text-muted-foreground">
            No scans initiated yet.
          </div>
        )}
      </div>
    </div>
  );
}
