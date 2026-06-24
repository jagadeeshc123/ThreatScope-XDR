import { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { apiClient } from '../api/client';
import type { SearchResults } from '../types';
import { Search, Target, Activity, AlertTriangle, FileText, ArrowRight } from 'lucide-react';
import { toast } from 'sonner';

export function SearchResultsPage() {
  const [searchParams] = useSearchParams();
  const query = searchParams.get('q') || '';
  const [results, setResults] = useState<SearchResults | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (query) {
      performSearch();
    } else {
      setLoading(false);
    }
  }, [query]);

  const performSearch = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get(`/search?q=${encodeURIComponent(query)}`);
      setResults(response.data);
    } catch (error) {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="p-6">Searching...</div>;
  }

  if (!query) {
    return <div className="p-6 text-muted-foreground">Please enter a search query.</div>;
  }

  const totalResults = results ? (results.targets.length + results.scans.length + results.findings.length + results.reports.length) : 0;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center space-x-3 mb-6">
        <Search className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold tracking-tight">Search Results for "{query}"</h1>
      </div>

      <p className="text-muted-foreground">Found {totalResults} total results.</p>

      {totalResults === 0 ? (
        <div className="py-12 text-center bg-card border border-border rounded-xl">
          <Search className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
          <h3 className="text-lg font-medium">No results found</h3>
          <p className="text-muted-foreground mt-2">Try adjusting your search terms or search for something else.</p>
        </div>
      ) : (
        <div className="space-y-8">
          
          {/* Targets */}
          {results?.targets && results.targets.length > 0 && (
            <div className="space-y-4">
              <h2 className="text-xl font-semibold flex items-center border-b pb-2">
                <Target className="w-5 h-5 mr-2 text-blue-500" />
                Targets ({results.targets.length})
              </h2>
              <div className="grid gap-3">
                {results.targets.map(t => (
                  <Link key={t.id} to={`/targets`} className="flex items-center justify-between p-4 bg-card border border-border rounded-lg hover:border-primary transition-colors group">
                    <div>
                      <div className="font-medium">{t.name}</div>
                      <div className="text-sm text-muted-foreground">{t.base_url}</div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Scans */}
          {results?.scans && results.scans.length > 0 && (
            <div className="space-y-4">
              <h2 className="text-xl font-semibold flex items-center border-b pb-2">
                <Activity className="w-5 h-5 mr-2 text-green-500" />
                Scans ({results.scans.length})
              </h2>
              <div className="grid gap-3">
                {results.scans.map(s => (
                  <Link key={s.id} to={`/scans?highlight=${s.id}`} className="flex items-center justify-between p-4 bg-card border border-border rounded-lg hover:border-primary transition-colors group">
                    <div>
                      <div className="font-medium">Scan #{s.id} - {s.profile}</div>
                      <div className="text-sm text-muted-foreground">Status: {s.status} | Risk Score: {s.risk_score}</div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Findings */}
          {results?.findings && results.findings.length > 0 && (
            <div className="space-y-4">
              <h2 className="text-xl font-semibold flex items-center border-b pb-2">
                <AlertTriangle className="w-5 h-5 mr-2 text-warning" />
                Findings ({results.findings.length})
              </h2>
              <div className="grid gap-3">
                {results.findings.map(f => (
                  <Link key={f.id} to={`/scans?highlight=${f.scan_id}`} className="flex items-center justify-between p-4 bg-card border border-border rounded-lg hover:border-primary transition-colors group">
                    <div>
                      <div className="font-medium flex items-center">
                        <span className={`w-2 h-2 rounded-full mr-2 ${f.severity === 'critical' ? 'bg-destructive' : f.severity === 'high' ? 'bg-orange-500' : 'bg-warning'}`}></span>
                        {f.title}
                      </div>
                      <div className="text-sm text-muted-foreground truncate max-w-2xl">{f.affected_url}</div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Reports */}
          {results?.reports && results.reports.length > 0 && (
            <div className="space-y-4">
              <h2 className="text-xl font-semibold flex items-center border-b pb-2">
                <FileText className="w-5 h-5 mr-2 text-purple-500" />
                Reports ({results.reports.length})
              </h2>
              <div className="grid gap-3">
                {results.reports.map(r => (
                  <Link key={r.id} to={`/reports`} className="flex items-center justify-between p-4 bg-card border border-border rounded-lg hover:border-primary transition-colors group">
                    <div>
                      <div className="font-medium">{r.title}</div>
                      <div className="text-sm text-muted-foreground">Generated at {new Date(r.created_at).toLocaleString()}</div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  </Link>
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
