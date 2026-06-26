import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import { ShieldCheck } from 'lucide-react';

interface PolicyCheck {
  id: string;
  title: string;
  expected_state: string;
  severity_impact: string;
}

interface PolicyPack {
  policy_id: string;
  title: string;
  description: string;
  checks: PolicyCheck[];
}

export function Policies() {
  const [policies, setPolicies] = useState<PolicyPack[]>([]);

  useEffect(() => {
    apiClient.get<PolicyPack[]>('/policies').then(res => setPolicies(res.data));
  }, []);

  return (
    <div className="p-8 space-y-8">
      <h1 className="text-3xl font-bold tracking-tight">Compliance Policies</h1>
      <p className="text-muted-foreground">Web application exposure baselines and security hardening standards.</p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {policies.map(p => (
          <div key={p.policy_id} className="bg-card border border-border rounded-xl p-6 shadow-sm">
            <div className="flex items-center mb-4">
              <div className="p-3 bg-primary/20 text-primary rounded-lg mr-4">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <h3 className="font-bold text-lg">{p.title}</h3>
                <p className="text-sm text-muted-foreground">{p.policy_id}</p>
              </div>
            </div>
            <p className="text-sm mb-6">{p.description}</p>
            
            <h4 className="font-bold text-sm text-muted-foreground uppercase tracking-wider mb-3">Checks</h4>
            <div className="space-y-3">
              {p.checks.map((c: any) => (
                <div key={c.id} className="bg-background border border-border p-3 rounded-md text-sm">
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-medium">{c.title}</span>
                    <span className={`text-xs px-2 py-0.5 rounded capitalize ${c.severity_impact === 'high' || c.severity_impact === 'critical' ? 'bg-destructive/20 text-destructive' : 'bg-muted text-muted-foreground'}`}>
                      {c.severity_impact} impact
                    </span>
                  </div>
                  <p className="text-muted-foreground text-xs">{c.expected_state}</p>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
