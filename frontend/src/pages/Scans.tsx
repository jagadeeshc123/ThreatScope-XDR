import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import type { Scan, Target, Finding } from '../types';
import { Play, Activity, ChevronRight, AlertTriangle, ShieldAlert } from 'lucide-react';
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
    try {
      const res = await apiClient.get<Finding[]>(`/scans/${scan.id}/findings`);
      setFindings(res.data);
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

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
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
