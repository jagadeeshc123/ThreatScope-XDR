import { useState, useEffect } from 'react';
import type { AppSettings } from '../types';
import { Save, RotateCcw } from 'lucide-react';
import { toast } from 'sonner';
import { getSettings, resetSettings as resetDemoSettings, updateSettings as updateDemoSettings } from '../data/demoData';

export function Settings() {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    setSettings(getSettings());
    setLoading(false);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settings) return;
    setSaving(true);
    try {
      updateDemoSettings(settings);
      toast.success('Settings saved successfully');
    } catch {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!confirm('Are you sure you want to reset all settings to defaults?')) return;
    try {
      setSettings(resetDemoSettings());
      toast.success('Settings reset to defaults');
    } catch {
      toast.error('Failed to reset settings');
    }
  };

  if (loading || !settings) return <div className="p-6">Loading settings...</div>;

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground mt-2">Configure scanner behavior, appearance, and report branding.</p>
      </div>

      <form onSubmit={handleSave} className="space-y-8">
        {/* Appearance */}
        <div className="bg-card border border-border rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold mb-4 border-b border-border pb-2">Appearance</h2>
          <div className="max-w-xs">
            <label className="text-sm font-medium mb-2 block">Theme</label>
            <select 
              value={settings.theme}
              onChange={e => setSettings({...settings, theme: e.target.value as any})}
              className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
            >
              <option value="dark">Dark</option>
              <option value="light">Light</option>
              <option value="system">System</option>
            </select>
          </div>
        </div>

        {/* Scanner Defaults */}
        <div className="bg-card border border-border rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold mb-4 border-b border-border pb-2">Scanner Defaults</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="text-sm font-medium mb-2 block">Default Scan Profile</label>
              <select 
                value={settings.default_scan_profile}
                onChange={e => setSettings({...settings, default_scan_profile: e.target.value})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              >
                <option value="Passive Scan">Passive Scan</option>
                <option value="Standard Safe Scan">Standard Safe Scan</option>
                <option value="Full Safe Scan">Full Safe Scan</option>
              </select>
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Request Timeout (seconds)</label>
              <input 
                type="number" 
                min="1" max="60"
                value={settings.request_timeout_seconds}
                onChange={e => setSettings({...settings, request_timeout_seconds: parseInt(e.target.value)})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Max Pages (Standard Scan)</label>
              <input 
                type="number" 
                min="1"
                value={settings.max_pages_standard}
                onChange={e => setSettings({...settings, max_pages_standard: parseInt(e.target.value)})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Max Pages (Full Scan)</label>
              <input 
                type="number" 
                min="1"
                value={settings.max_pages_full}
                onChange={e => setSettings({...settings, max_pages_full: parseInt(e.target.value)})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              />
            </div>
          </div>
        </div>

        {/* Report Branding */}
        <div className="bg-card border border-border rounded-xl shadow-sm p-6">
          <h2 className="text-lg font-semibold mb-4 border-b border-border pb-2">Report Branding</h2>
          <div className="space-y-4 max-w-xl">
            <div>
              <label className="text-sm font-medium mb-2 block">Report Company Name</label>
              <input 
                type="text" 
                value={settings.report_company_name}
                onChange={e => setSettings({...settings, report_company_name: e.target.value})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Footer / Disclaimer Text</label>
              <textarea 
                rows={3}
                value={settings.report_footer_text}
                onChange={e => setSettings({...settings, report_footer_text: e.target.value})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary resize-none"
              />
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-between items-center pt-4">
          <button 
            type="button"
            onClick={handleReset}
            className="text-destructive hover:bg-destructive/10 px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center"
          >
            <RotateCcw className="w-4 h-4 mr-2" />
            Reset Defaults
          </button>
          
          <button 
            type="submit" 
            disabled={saving}
            className="bg-primary text-primary-foreground hover:bg-primary/90 px-6 py-2.5 rounded-md text-sm font-medium transition-colors flex items-center disabled:opacity-50"
          >
            <Save className="w-4 h-4 mr-2" />
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </form>
    </div>
  );
}
