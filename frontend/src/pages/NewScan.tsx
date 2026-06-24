import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { apiClient } from '../api/client';
import type { Target } from '../types';
import { Target as TargetIcon, Play, AlertCircle, ArrowLeft } from 'lucide-react';
import { toast } from 'sonner';

export function NewScan() {
  const [searchParams] = useSearchParams();
  const targetIdParam = searchParams.get('targetId');
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string>(targetIdParam || '');
  const [profile, setProfile] = useState('Standard Safe Scan');
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    try {
      const response = await apiClient.get('/targets');
      setTargets(response.data);
      if (!selectedTargetId && response.data.length > 0) {
        setSelectedTargetId(response.data[0].id.toString());
      }
    } catch (error) {
      toast.error('Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTargetId) return;

    setStarting(true);
    try {
      const response = await apiClient.post('/scans/start', null, {
        params: {
          target_id: selectedTargetId,
          profile: profile
        }
      });
      toast.success('Scan started successfully!');
      navigate(`/scans?highlight=${response.data.id}`);
    } catch (error) {
      toast.error('Failed to start scan. Ensure the target exists and is authorized.');
    } finally {
      setStarting(false);
    }
  };

  if (loading) {
    return <div className="p-6 text-muted-foreground">Loading targets...</div>;
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="mb-6 flex items-center">
        <button onClick={() => navigate(-1)} className="mr-4 p-2 hover:bg-muted rounded-full transition-colors">
          <ArrowLeft className="h-5 w-5 text-muted-foreground" />
        </button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">New Scan</h1>
          <p className="text-muted-foreground mt-2">Configure and launch a new security assessment.</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
        <form onSubmit={handleStartScan} className="p-6 space-y-8">
          {/* Target Selection */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold flex items-center">
              <TargetIcon className="w-5 h-5 mr-2 text-primary" />
              1. Select Target
            </h2>
            <div className="ml-7">
              {targets.length === 0 ? (
                <div className="p-4 bg-muted/50 rounded-lg text-sm flex items-start">
                  <AlertCircle className="w-5 h-5 text-warning mr-2 shrink-0" />
                  <div>
                    <p className="font-medium text-warning">No targets available</p>
                    <p className="text-muted-foreground mt-1">You must add an authorized target before launching a scan.</p>
                    <button type="button" onClick={() => navigate('/targets')} className="mt-3 text-primary hover:underline font-medium">
                      Go to Targets
                    </button>
                  </div>
                </div>
              ) : (
                <select
                  className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  value={selectedTargetId}
                  onChange={(e) => setSelectedTargetId(e.target.value)}
                  required
                >
                  <option value="" disabled>Select a target...</option>
                  {targets.map(t => (
                    <option key={t.id} value={t.id}>{t.name} ({t.base_url})</option>
                  ))}
                </select>
              )}
            </div>
          </div>

          {/* Profile Selection */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold flex items-center">
              <Play className="w-5 h-5 mr-2 text-primary" />
              2. Scan Profile
            </h2>
            <div className="ml-7 grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { id: 'Passive Scan', title: 'Passive Scan', desc: 'Header analysis only. Zero crawler traffic.', time: '~2s' },
                { id: 'Standard Safe Scan', title: 'Standard Safe Scan', desc: 'Light crawling (25 pages). Checks all basic misconfigurations.', time: '~30s' },
                { id: 'Full Safe Scan', title: 'Full Safe Scan', desc: 'Deep crawling (50+ pages). Comprehensive passive checks.', time: '~2m' }
              ].map(p => (
                <div 
                  key={p.id}
                  onClick={() => setProfile(p.id)}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${profile === p.id ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-muted-foreground/50 bg-card'}`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <h3 className="font-medium">{p.title}</h3>
                    <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${profile === p.id ? 'border-primary' : 'border-muted-foreground'}`}>
                      {profile === p.id && <div className="w-2 h-2 rounded-full bg-primary" />}
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground mb-3">{p.desc}</p>
                  <span className="text-xs font-mono bg-muted px-2 py-1 rounded">Est: {p.time}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="ml-7 pt-4 border-t border-border">
            <button
              type="submit"
              disabled={starting || targets.length === 0}
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-6 py-2.5 rounded-md text-sm font-medium transition-colors flex items-center disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {starting ? (
                <>
                  <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin mr-2" />
                  Starting...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 mr-2" />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
