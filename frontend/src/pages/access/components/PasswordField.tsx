import { useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';

export function PasswordField({ label, value, onChange, autoComplete = 'current-password', required = true }: { label: string; value: string; onChange: (value: string) => void; autoComplete?: string; required?: boolean }) {
  const [visible, setVisible] = useState(false);
  return <label className="block text-sm font-medium">{label}<span className="mt-2 flex rounded-md border border-input bg-background focus-within:ring-2 focus-within:ring-primary"><input className="min-w-0 flex-1 bg-transparent px-3 py-2 outline-none" type={visible ? 'text' : 'password'} value={value} onChange={event => onChange(event.target.value)} autoComplete={autoComplete} required={required} maxLength={128}/><button type="button" onClick={() => setVisible(current => !current)} className="px-3 text-muted-foreground" aria-label={visible ? `Hide ${label}` : `Show ${label}`}>{visible ? <EyeOff className="h-4 w-4"/> : <Eye className="h-4 w-4"/>}</button></span></label>;
}
