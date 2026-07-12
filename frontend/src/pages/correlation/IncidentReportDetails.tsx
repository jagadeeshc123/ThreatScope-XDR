import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import type { IncidentReport } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { PageShell } from '../../components/ui';

export function IncidentReportDetails() {
  const { reportId } = useParams();
  const [report, setReport] = useState<IncidentReport | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    void vulnscopeApi.getIncidentReport(Number(reportId)).then(setReport).catch(() => setError(true));
  }, [reportId]);

  if (error) return <PageShell><p className="text-destructive">Incident report not found.</p></PageShell>;
  if (!report) return <PageShell>Loading report...</PageShell>;
  return <PageShell className="max-w-none"><iframe sandbox="" title={report.title} srcDoc={report.html_content} className="min-h-[80vh] w-full rounded bg-white" /></PageShell>;
}
