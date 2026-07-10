import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowRight, FileJson, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import type { ApiAssessmentDetail, ApiImportResult, ApiSourceType } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { EmptyState, PageHeader, PageShell, SectionCard } from '../../components/ui';
import { ImportDropzone } from './components/ImportDropzone';

export function ImportApiDefinition() {
  const { assessmentId } = useParams();
  const numericId = Number(assessmentId);
  const [assessment, setAssessment] = useState<ApiAssessmentDetail | null>(null);
  const [sourceType, setSourceType] = useState<ApiSourceType>('openapi');
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<ApiImportResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!numericId) return;
    let cancelled = false;
    vulnscopeApi.getApiAssessment(numericId)
      .then(data => {
        if (cancelled) return;
        setAssessment(data);
        if (data.source_type !== 'manual') setSourceType(data.source_type);
      })
      .catch(() => { if (!cancelled) setError('Assessment could not be loaded.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [numericId]);

  async function upload() {
    if (!file || !assessment) return;
    setUploading(true);
    setError(null);
    try {
      const imported = sourceType === 'openapi'
        ? await vulnscopeApi.importOpenApi(assessment.id, file)
        : await vulnscopeApi.importPostman(assessment.id, file);
      setResult(imported);
      toast.success(`${imported.endpoints_discovered} endpoints imported`);
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Import failed validation.';
      setError(detail);
      toast.error(detail);
    } finally {
      setUploading(false);
    }
  }

  if (loading) return <PageShell><div className="text-muted-foreground">Loading assessment...</div></PageShell>;
  if (!assessment) return <PageShell><EmptyState title="Assessment unavailable" description={error || 'The assessment could not be found.'} /></PageShell>;

  const accept = sourceType === 'openapi' ? '.json,.yaml,.yml,application/json,application/yaml,text/yaml' : '.json,application/json';

  return (
    <PageShell className="max-w-5xl">
      <PageHeader title="Import API Definition" subtitle={assessment.name} />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <SectionCard>
          <div className="space-y-5">
            <label className="block text-sm font-medium text-foreground">
              Import format
              <select value={sourceType} onChange={event => { setSourceType(event.target.value as ApiSourceType); setFile(null); setResult(null); }} className="mt-2 w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:border-indigo-400">
                <option value="openapi">OpenAPI JSON/YAML</option>
                <option value="postman">Postman Collection v2.1 JSON</option>
              </select>
            </label>
            <ImportDropzone accept={accept} disabled={uploading} file={file} onFile={setFile} />
            <div className="rounded-md border border-border bg-background/60 p-4 text-sm leading-6 text-muted-foreground">
              {sourceType === 'openapi' ? 'Accepted: .json, .yaml, .yml. OpenAPI 3.x only. Remote references are not resolved.' : 'Accepted: .json. Postman Collection v2.1 only. Requests are parsed as metadata and never executed.'}
            </div>
            {error && <div className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-200">{error}</div>}
            <button onClick={() => void upload()} disabled={!file || uploading} className="inline-flex h-10 items-center gap-2 rounded-md bg-indigo-500 px-4 text-sm font-semibold text-white hover:bg-indigo-400 disabled:opacity-60">
              {uploading ? 'Importing...' : 'Import definition'} <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </SectionCard>
        <SectionCard title="Import Result" icon={<FileJson className="h-5 w-5" />}>
          {result ? (
            <div className="space-y-4 text-sm">
              <ResultLine label="Endpoints discovered" value={result.endpoints_discovered} />
              <ResultLine label="Unauthenticated" value={result.unauthenticated_endpoints} />
              <ResultLine label="High risk" value={result.high_risk_endpoints} />
              <div className="rounded-md border border-emerald-400/30 bg-emerald-500/10 p-3 text-emerald-200">
                <ShieldCheck className="mb-2 h-4 w-4" />
                Import completed with redacted artifact storage.
              </div>
              <Link to={`/api-security/assessments/${assessment.id}/endpoints`} className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm font-semibold hover:bg-muted">View endpoints <ArrowRight className="h-4 w-4" /></Link>
            </div>
          ) : (
            <p className="text-sm leading-6 text-muted-foreground">Import results will appear after a valid definition is uploaded.</p>
          )}
        </SectionCard>
      </div>
    </PageShell>
  );
}

function ResultLine({ label, value }: { label: string; value: number }) {
  return <div className="flex items-center justify-between border-b border-border pb-2"><span className="text-muted-foreground">{label}</span><span className="font-semibold">{value}</span></div>;
}
