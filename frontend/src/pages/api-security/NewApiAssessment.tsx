import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import { toast } from 'sonner';
import type { ApiSourceType } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { PageHeader, PageShell, SectionCard } from '../../components/ui';

export function NewApiAssessment() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [sourceType, setSourceType] = useState<ApiSourceType>('openapi');
  const [saving, setSaving] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    try {
      const assessment = await vulnscopeApi.createApiAssessment({
        name,
        description: description.trim() || null,
        source_type: sourceType,
      });
      toast.success('API assessment created');
      navigate(`/api-security/assessments/${assessment.id}/import`);
    } catch {
      toast.error('Assessment could not be created');
    } finally {
      setSaving(false);
    }
  }

  return (
    <PageShell className="max-w-4xl">
      <PageHeader title="New API Assessment" subtitle="Set up a passive API assessment workspace before importing a definition file." />
      <SectionCard>
        <form onSubmit={submit} className="space-y-5">
          <label className="block text-sm font-medium text-foreground">
            Name
            <input value={name} onChange={event => setName(event.target.value)} required minLength={2} maxLength={160} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:border-indigo-400" />
          </label>
          <label className="block text-sm font-medium text-foreground">
            Description
            <textarea value={description} onChange={event => setDescription(event.target.value)} rows={4} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:border-indigo-400" />
          </label>
          <label className="block text-sm font-medium text-foreground">
            Source type
            <select value={sourceType} onChange={event => setSourceType(event.target.value as ApiSourceType)} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:border-indigo-400">
              <option value="openapi">OpenAPI</option>
              <option value="postman">Postman Collection</option>
              <option value="manual">Manual</option>
            </select>
          </label>
          <button disabled={saving} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white transition-colors hover:bg-indigo-400 disabled:opacity-60">
            {saving ? 'Creating...' : 'Create and import'} <ArrowRight className="h-4 w-4" />
          </button>
        </form>
      </SectionCard>
    </PageShell>
  );
}
