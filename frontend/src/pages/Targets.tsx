import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import type { Target } from '../types';
import { Plus, Trash2, ShieldCheck, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';

export function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  const [formData, setFormData] = useState({
    name: '',
    base_url: '',
    environment: 'development',
    authorization_confirmed: false,
  });

  const fetchTargets = async () => {
    try {
      const res = await apiClient.get<Target[]>('/targets');
      setTargets(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.authorization_confirmed) return;
    try {
      await apiClient.post('/targets', formData);
      setShowForm(false);
      setFormData({ name: '', base_url: '', environment: 'development', authorization_confirmed: false });
      fetchTargets();
    } catch (err) {
      console.error(err);
      alert('Failed to add target');
    }
  };

  const deleteTarget = async (id: number) => {
    if (!confirm('Are you sure you want to delete this target?')) return;
    try {
      await apiClient.delete(`/targets/${id}`);
      fetchTargets();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="p-8 space-y-8">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold tracking-tight">Targets</h1>
        <button 
          onClick={() => setShowForm(!showForm)}
          className="flex items-center bg-primary text-primary-foreground px-4 py-2 rounded-md hover:bg-primary/90 font-medium transition-colors"
        >
          <Plus className="w-5 h-5 mr-2" />
          Add Target
        </button>
      </div>

      {showForm && (
        <div className="bg-card border border-border rounded-xl p-6 shadow-sm max-w-2xl">
          <h2 className="text-xl font-bold mb-4">Add New Target</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Target Name</label>
              <input required type="text" className="w-full bg-background border border-input rounded-md px-3 py-2" value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})} />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Base URL</label>
              <input required type="url" placeholder="https://example.com" className="w-full bg-background border border-input rounded-md px-3 py-2" value={formData.base_url} onChange={e => setFormData({...formData, base_url: e.target.value})} />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Environment</label>
              <select className="w-full bg-background border border-input rounded-md px-3 py-2" value={formData.environment} onChange={e => setFormData({...formData, environment: e.target.value})}>
                <option value="development">Development</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
              </select>
            </div>
            <div className="flex items-start mt-4 p-4 border border-destructive/30 bg-destructive/5 rounded-md">
              <input required type="checkbox" id="auth" className="mt-1" checked={formData.authorization_confirmed} onChange={e => setFormData({...formData, authorization_confirmed: e.target.checked})} />
              <label htmlFor="auth" className="ml-3 text-sm text-muted-foreground">
                <strong className="block text-foreground mb-1">Authorization Confirmation</strong>
                I confirm that I own this system or have explicit permission to conduct security testing on this target. I will not use VulnScope for malicious purposes.
              </label>
            </div>
            <div className="flex justify-end space-x-3 pt-4">
              <button type="button" onClick={() => setShowForm(false)} className="px-4 py-2 border border-border rounded-md hover:bg-muted">Cancel</button>
              <button type="submit" disabled={!formData.authorization_confirmed} className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50">Save Target</button>
            </div>
          </form>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {targets.map(target => (
          <div key={target.id} className="bg-card border border-border rounded-xl p-6 shadow-sm relative group flex flex-col">
            <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity">
              <button onClick={() => deleteTarget(target.id)} className="text-destructive hover:bg-destructive/10 p-2 rounded-md">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1">
              <h3 className="font-bold text-lg mb-1">{target.name}</h3>
              <p className="text-sm text-muted-foreground mb-4">{target.base_url}</p>
              
              <div className="flex items-center space-x-2 text-xs mb-4">
                <span className="bg-secondary px-2 py-1 rounded capitalize">{target.environment}</span>
                {target.authorization_confirmed ? (
                  <span className="flex items-center text-primary bg-primary/10 px-2 py-1 rounded"><ShieldCheck className="w-3 h-3 mr-1"/> Authorized</span>
                ) : (
                  <span className="flex items-center text-destructive bg-destructive/10 px-2 py-1 rounded"><ShieldAlert className="w-3 h-3 mr-1"/> Unauthorized</span>
                )}
              </div>
            </div>
            
            <div className="mt-4 pt-4 border-t border-border flex justify-between">
              <Link to={`/scans/new?targetId=${target.id}`} className="text-primary hover:underline text-sm font-medium">New Scan</Link>
            </div>
          </div>
        ))}
        {!loading && targets.length === 0 && (
          <div className="col-span-full py-12 text-center text-muted-foreground border-2 border-dashed border-border rounded-xl">
            No targets added yet. Click "Add Target" to get started.
          </div>
        )}
      </div>
    </div>
  );
}
