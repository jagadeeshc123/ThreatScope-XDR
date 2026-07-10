import type { ReactNode } from 'react';
import clsx from 'clsx';
import { AlertTriangle, FileText, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { PolicyPack } from '../api/vulnscope';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
type Status = 'queued' | 'running' | 'completed' | 'failed' | 'passed' | string;

export function PageShell({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={clsx('mx-auto w-full max-w-7xl px-5 py-6 sm:px-6 lg:px-8 space-y-6', className)}>
      {children}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">{title}</h1>
        {subtitle && <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground sm:text-base">{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-3">{actions}</div>}
    </div>
  );
}

export function SectionCard({
  title,
  subtitle,
  icon,
  children,
  className,
  bodyClassName,
}: {
  title?: string;
  subtitle?: string;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={clsx('rounded-lg border border-border/80 bg-card/90 shadow-sm shadow-black/10', className)}>
      {(title || subtitle || icon) && (
        <div className="flex items-start justify-between gap-4 border-b border-border/70 px-5 py-4">
          <div>
            {title && <h2 className="text-base font-semibold text-foreground sm:text-lg">{title}</h2>}
            {subtitle && <p className="mt-1 text-sm leading-6 text-muted-foreground">{subtitle}</p>}
          </div>
          {icon && <div className="mt-0.5 text-primary">{icon}</div>}
        </div>
      )}
      <div className={clsx('p-5', bodyClassName)}>{children}</div>
    </section>
  );
}

export function StatCard({
  label,
  value,
  detail,
  icon,
  tone = 'default',
}: {
  label: string;
  value: ReactNode;
  detail?: string;
  icon?: ReactNode;
  tone?: 'default' | 'good' | 'warn' | 'danger' | 'info';
}) {
  const toneClass = {
    default: 'bg-secondary/50 text-secondary-foreground',
    good: 'bg-primary/15 text-primary',
    warn: 'bg-amber-500/15 text-amber-300',
    danger: 'bg-red-500/15 text-red-300',
    info: 'bg-blue-500/15 text-blue-300',
  }[tone];

  return (
    <div className="min-h-[132px] rounded-lg border border-border/80 bg-card/90 p-5 shadow-sm shadow-black/10">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm font-medium text-muted-foreground">{label}</p>
        {icon && <div className={clsx('rounded-md p-2', toneClass)}>{icon}</div>}
      </div>
      <div className="mt-4 text-3xl font-semibold tracking-tight text-foreground">{value}</div>
      {detail && <p className="mt-2 text-sm leading-5 text-muted-foreground">{detail}</p>}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const normalized = severity.toLowerCase();
  const classes =
    normalized === 'critical'
      ? 'border-red-400/50 bg-red-500/15 text-red-200'
      : normalized === 'high'
        ? 'border-orange-400/50 bg-orange-500/15 text-orange-200'
        : normalized === 'medium'
          ? 'border-amber-400/50 bg-amber-500/15 text-amber-100'
          : normalized === 'low'
            ? 'border-blue-400/50 bg-blue-500/15 text-blue-200'
            : 'border-slate-400/40 bg-slate-500/15 text-slate-200';

  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold capitalize leading-none', classes)}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: Status }) {
  const normalized = status.toLowerCase();
  const classes =
    normalized === 'completed' || normalized === 'passed'
      ? 'border-emerald-400/50 bg-emerald-500/15 text-emerald-200'
      : normalized === 'running'
        ? 'border-blue-400/50 bg-blue-500/15 text-blue-200'
        : normalized === 'failed'
          ? 'border-red-400/50 bg-red-500/15 text-red-200'
          : 'border-slate-400/40 bg-slate-500/15 text-slate-200';

  return (
    <span className={clsx('inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold capitalize leading-none', classes)}>
      {status}
    </span>
  );
}

export function RiskScoreBadge({ score, max = 10 }: { score: number; max?: number }) {
  const tone = score >= 8 ? 'text-red-200' : score >= 6 ? 'text-orange-200' : score >= 4 ? 'text-amber-100' : 'text-emerald-200';
  const fill = Math.max(0, Math.min(100, (score / max) * 100));

  return (
    <div className="min-w-[120px]">
      <div className="mb-1 flex items-baseline justify-between gap-2">
        <span className={clsx('text-sm font-semibold', tone)}>{score.toFixed(1)}</span>
        <span className="text-xs text-muted-foreground">/{max}</span>
      </div>
      <div className="h-2 rounded-full bg-muted">
        <div className="h-full rounded-full bg-gradient-to-r from-emerald-400 via-amber-400 to-red-500" style={{ width: `${fill}%` }} />
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon = <Search className="h-8 w-8" />,
}: {
  title: string;
  description: string;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-card/60 px-6 py-12 text-center">
      <div className="mb-4 rounded-full bg-muted p-3 text-muted-foreground">{icon}</div>
      <h3 className="text-base font-semibold text-foreground">{title}</h3>
      <p className="mt-2 max-w-md text-sm leading-6 text-muted-foreground">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function FindingCard({ finding, compact = false }: { finding: any; compact?: boolean }) {
  return (
    <article className="rounded-lg border border-border/80 bg-background/50 p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="text-sm text-muted-foreground">{finding.category}</span>
          </div>
          <h3 className="mt-2 text-base font-semibold text-foreground">{finding.title}</h3>
          <p className="mt-1 break-all font-mono text-xs leading-5 text-muted-foreground">{finding.affected_url}</p>
        </div>
        <div className="text-sm text-muted-foreground">Confidence: <span className="font-medium capitalize text-foreground">{finding.confidence}</span></div>
      </div>
      <p className="mt-3 text-sm leading-6 text-muted-foreground">{finding.description}</p>
      {!compact && (
        <div className="mt-4 grid gap-3 lg:grid-cols-3">
          <InfoBlock title="Evidence" icon={<FileText className="h-4 w-4" />} text={finding.evidence} />
          <InfoBlock title="Impact" icon={<AlertTriangle className="h-4 w-4" />} text={finding.impact} />
          <InfoBlock title="Remediation" icon={<ShieldCheck className="h-4 w-4" />} text={finding.remediation} />
        </div>
      )}
    </article>
  );
}

function InfoBlock({ title, icon, text }: { title: string; icon: ReactNode; text: string }) {
  return (
    <div className="rounded-md border border-border bg-card/70 p-3">
      <p className="mb-2 flex items-center gap-2 text-sm font-semibold text-foreground">{icon}{title}</p>
      <p className="text-sm leading-6 text-muted-foreground">{text}</p>
    </div>
  );
}

export function PolicyCard({ policy }: { policy: PolicyPack }) {
  return (
    <SectionCard className="h-full" bodyClassName="space-y-4">
      <div className="flex items-start gap-4">
        <div className="rounded-md bg-primary/15 p-3 text-primary">
          <ShieldAlert className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <h3 className="text-lg font-semibold text-foreground">{policy.title}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{policy.policy_id}</p>
        </div>
        <span className="ml-auto rounded-full border border-border bg-muted px-3 py-1 text-xs font-medium text-foreground">
          {policy.checks.length} checks
        </span>
      </div>
      <p className="text-sm leading-6 text-muted-foreground">{policy.description}</p>
      <div className="space-y-3">
        {policy.checks.map(check => (
          <div key={check.id} className="rounded-md border border-border bg-background/60 p-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <p className="text-sm font-medium text-foreground">{check.title}</p>
              <SeverityBadge severity={check.severity_impact} />
            </div>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">{check.expected_state}</p>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}
