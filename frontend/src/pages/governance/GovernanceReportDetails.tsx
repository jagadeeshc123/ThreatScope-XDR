import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import type { GovernanceReport } from '../../types';
import { vulnscopeApi } from '../../api/vulnscope';
import { PageHeader, PageShell } from '../../components/ui';

export function GovernanceReportDetails() {
  const { reportId } = useParams();
  const [report, setReport] = useState<GovernanceReport | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    void vulnscopeApi.getGovernanceReport(Number(reportId)).then(setReport).catch(() => setError(true));
  }, [reportId]);

  if (error) return <PageShell><p className="text-destructive">Governance report not found.</p></PageShell>;
  if (!report) return <PageShell>Loading governance report...</PageShell>;
  return <PageShell><PageHeader title={report.title} subtitle="Safe server-generated and escaped HTML report." /><iframe title={report.title} srcDoc={report.html_content} className="min-h-[70vh] w-full rounded border bg-white" sandbox="allow-same-origin" /></PageShell>;
}
