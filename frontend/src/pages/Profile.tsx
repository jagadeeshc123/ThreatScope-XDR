import { useState, useEffect } from 'react';
import { Save } from 'lucide-react';
import { toast } from 'sonner';
import { getProfile, updateProfile as updateDemoProfile } from '../data/demoData';

export function Profile() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [formData, setFormData] = useState({
    full_name: '',
    email: '',
    organization: '',
    role: '',
    avatar_initials: ''
  });

  useEffect(() => {
    fetchProfile();
  }, []);

  const fetchProfile = async () => {
    const profile = getProfile();
    setFormData({
      full_name: profile.full_name,
      email: profile.email,
      organization: profile.organization,
      role: profile.role,
      avatar_initials: profile.avatar_initials,
    });
    setLoading(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      updateDemoProfile(formData);
      toast.success('Profile updated successfully');
      // Update topbar instantly by dispatching event if needed, but fetchProfile runs on intervals
    } catch {
      toast.error('Failed to update profile');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="p-6">Loading profile...</div>;

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Profile</h1>
        <p className="text-muted-foreground mt-2">Manage your account details and organizational context.</p>
      </div>

      <div className="bg-card border border-border rounded-xl shadow-sm p-6">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-sm font-medium">Full Name</label>
              <input 
                type="text" 
                value={formData.full_name}
                onChange={e => setFormData({...formData, full_name: e.target.value})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Email Address</label>
              <input 
                type="email" 
                value={formData.email}
                onChange={e => setFormData({...formData, email: e.target.value})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Organization</label>
              <input 
                type="text" 
                value={formData.organization}
                onChange={e => setFormData({...formData, organization: e.target.value})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Role</label>
              <input 
                type="text" 
                value={formData.role}
                onChange={e => setFormData({...formData, role: e.target.value})}
                className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Avatar Initials</label>
              <input 
                type="text" 
                maxLength={3}
                value={formData.avatar_initials}
                onChange={e => setFormData({...formData, avatar_initials: e.target.value.toUpperCase()})}
                className="w-24 bg-background border border-input rounded-md px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              />
            </div>
          </div>
          
          <div className="pt-4 border-t border-border flex justify-end">
            <button 
              type="submit" 
              disabled={saving}
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-4 py-2 rounded-md text-sm font-medium transition-colors flex items-center disabled:opacity-50"
            >
              <Save className="w-4 h-4 mr-2" />
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
