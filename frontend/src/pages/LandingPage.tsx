import { Link } from 'react-router-dom';
import { Shield, Lock, Activity, ShieldAlert, CheckCircle } from 'lucide-react';

export function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col">
      <header className="h-20 border-b border-border flex items-center justify-between px-8">
        <div className="flex items-center">
          <Shield className="w-8 h-8 text-primary mr-3" />
          <span className="font-bold text-2xl tracking-wider">VulnScope</span>
        </div>
        <Link to="/dashboard" className="px-6 py-2.5 bg-primary text-primary-foreground font-medium rounded-md hover:bg-primary/90 transition-colors">
          Open Dashboard
        </Link>
      </header>

      <main className="flex-1 flex flex-col items-center justify-center p-8 text-center max-w-4xl mx-auto space-y-12">
        <div className="space-y-6">
          <div className="inline-flex items-center px-4 py-2 rounded-full border border-primary/30 bg-primary/10 text-primary text-sm font-medium mb-4">
            <Lock className="w-4 h-4 mr-2" /> Safe, Authorized Reconnaissance Only
          </div>
          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tighter leading-tight bg-gradient-to-br from-white to-gray-500 bg-clip-text text-transparent">
            Web Application Exposure & <br /> Security Posture Assessment.
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Continuously evaluate browser-facing web applications for configuration weaknesses, exposed public resources, client-side security risks, and security posture drift.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full text-left pt-12 border-t border-border/50">
          <div className="p-6 bg-card border border-border rounded-xl">
            <div className="w-12 h-12 bg-primary/20 rounded-lg flex items-center justify-center text-primary mb-6">
              <Activity className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-3">Web Exposure Monitoring</h3>
            <p className="text-muted-foreground leading-relaxed">
              Analyze headers, cookies, TLS misconfigurations, and technology disclosures by mapping the client-side surface safely.
            </p>
          </div>
          <div className="p-6 bg-card border border-border rounded-xl">
            <div className="w-12 h-12 bg-secondary/30 rounded-lg flex items-center justify-center text-secondary-foreground mb-6">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-3">Posture Drift & Scoring</h3>
            <p className="text-muted-foreground leading-relaxed">
              Automatically calculate security posture scores across multiple categories and track scan-to-scan configuration drift.
            </p>
          </div>
          <div className="p-6 bg-card border border-border rounded-xl">
            <div className="w-12 h-12 bg-accent/30 rounded-lg flex items-center justify-center text-accent-foreground mb-6">
              <CheckCircle className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-3">Evidence-Based Reporting</h3>
            <p className="text-muted-foreground leading-relaxed">
              Generate structured posture reports containing visual evidence, crawl maps, and compliance checklists.
            </p>
          </div>
        </div>
      </main>

      <footer className="py-6 border-t border-border text-center text-sm text-muted-foreground">
        VulnScope - Built for authorized web application exposure monitoring.
      </footer>
    </div>
  );
}
