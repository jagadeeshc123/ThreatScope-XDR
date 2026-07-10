import { useState, useEffect } from 'react';
import type { AppSettings } from '../types';
import { Save, RotateCcw } from 'lucide-react';
import { toast } from 'sonner';
import { vulnscopeApi } from '../api/vulnscope';

export function Settings() {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    setLoading(true);
    setError(null);
    try {
      setSettings(await vulnscopeApi.getSettings());
    } catch {
      setError('Settings could not be loaded from the backend.');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await vulnscopeApi.updateSettings({
        theme: settings.theme,
        default_scan_profile: settings.default_scan_profile,
        request_timeout_seconds: settings.request_timeout_seconds,
        max_pages_standard: settings.max_pages_standard,
        max_pages_full: settings.max_pages_full,
        max_depth_standard: settings.max_depth_standard,
        max_depth_full: settings.max_depth_full,
        rate_limit_delay_ms: settings.rate_limit_delay_ms,
        report_company_name: settings.report_company_name,
        report_footer_text: settings.report_footer_text,
        auto_generate_report: settings.auto_generate_report,
      });
      setSettings(updated);
      toast.success('Settings saved successfully');
    } catch {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!confirm('Are you sure you want to reset all settings to defaults?')) return;
    setResetting(true);
    try {
      setSettings(await vulnscopeApi.resetSettings());
      toast.success('Settings reset to defaults');
    } catch {
      toast.error('Failed to reset settings');
    } finally {
      setResetting(false);
    }
  };

  if (loading) return <div className="p-6 text-muted-foreground">Loading settings...</div>;
  if (error || !settings) return <div className="mx-auto max-w-4xl p-8 text-center"><h1 className="text-xl font-semibold">Settings unavailable</h1><p className="mt-2 text-sm text-muted-foreground">{error}</p><button onClick={() => void fetchSettings()} className="mt-4 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Try Again</button></div>;

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
              onChange={e => setSettings({...settings, theme: e.target.value as AppSettings['theme']})}
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
              <label className="text-sm font-medium mb-2 block">Max Crawl Depth (Standard Scan)</label>
              <input type="number" min="0" max="10" value={settings.max_depth_standard} onChange={e => setSettings({...settings, max_depth_standard: Number(e.target.value)})} className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary" />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Max Crawl Depth (Full Scan)</label>
              <input type="number" min="0" max="10" value={settings.max_depth_full} onChange={e => setSettings({...settings, max_depth_full: Number(e.target.value)})} className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary" />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Rate Limit Delay (milliseconds)</label>
              <input type="number" min="0" max="10000" step="50" value={settings.rate_limit_delay_ms} onChange={e => setSettings({...settings, rate_limit_delay_ms: Number(e.target.value)})} className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary" />
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
            <label className="flex items-center gap-3 rounded-md border border-border bg-background/60 p-3 text-sm font-medium">
              <input type="checkbox" checked={settings.auto_generate_report} onChange={e => setSettings({...settings, auto_generate_report: e.target.checked})} className="h-4 w-4 accent-primary" />
              Automatically generate a report when a scan completes
            </label>
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
            disabled={resetting || saving}
            className="text-destructive hover:bg-destructive/10 px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center"
          >
            <RotateCcw className="w-4 h-4 mr-2" />
            {resetting ? 'Resetting...' : 'Reset Defaults'}
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
