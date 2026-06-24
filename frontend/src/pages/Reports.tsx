import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import type { Report } from '../types';
import { Download, FileText, Eye } from 'lucide-react';

export function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedHtml, setSelectedHtml] = useState<string | null>(null);

  const fetchReports = async () => {
    try {
      const res = await apiClient.get<Report[]>('/reports');
      setReports(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleDownload = async (reportId: number) => {
    window.open(`${apiClient.defaults.baseURL}/reports/${reportId}/download`, '_blank');
  };

  if (selectedHtml) {
    return (
      <div className="p-8 space-y-6 h-full flex flex-col">
        <button onClick={() => setSelectedHtml(null)} className="text-muted-foreground hover:text-foreground text-sm flex items-center">
          ← Back to Reports
        </button>
        <div className="flex-1 bg-white rounded-xl overflow-hidden shadow-lg border border-border">
          <iframe srcDoc={selectedHtml} className="w-full h-full bg-white" title="Report Preview" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8">
      <h1 className="text-3xl font-bold tracking-tight">Assessment Reports</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {reports.map(report => (
          <div key={report.id} className="bg-card border border-border rounded-xl p-6 shadow-sm flex flex-col">
            <div className="flex items-start justify-between mb-4">
              <div className="p-3 bg-secondary/20 text-secondary-foreground rounded-lg">
                <FileText className="w-6 h-6" />
              </div>
              <span className="text-xs text-muted-foreground">{new Date(report.created_at).toLocaleDateString()}</span>
            </div>
            <h3 className="font-bold text-lg mb-2">{report.title}</h3>
            <p className="text-sm text-muted-foreground flex-1 mb-6">{report.executive_summary}</p>
            
            <div className="flex space-x-3 mt-auto">
              <button 
                onClick={() => setSelectedHtml(report.html_content)}
                className="flex-1 flex items-center justify-center bg-secondary text-secondary-foreground px-4 py-2 rounded-md hover:bg-secondary/80 text-sm font-medium"
              >
                <Eye className="w-4 h-4 mr-2" /> View
              </button>
              <button 
                onClick={() => handleDownload(report.id)}
                className="flex-1 flex items-center justify-center border border-border px-4 py-2 rounded-md hover:bg-muted text-sm font-medium"
              >
                <Download className="w-4 h-4 mr-2" /> Download
              </button>
            </div>
          </div>
        ))}
        
        {!loading && reports.length === 0 && (
          <div className="col-span-full py-16 text-center text-muted-foreground border-2 border-dashed border-border rounded-xl">
            No reports generated yet. Go to a completed scan to generate a report.
          </div>
        )}
      </div>
    </div>
  );
}
