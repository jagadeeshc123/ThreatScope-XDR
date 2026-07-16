export const routePermissions: Array<[string, string]> = [
  ['/operations/backups', 'operations:backup'], ['/operations/restores', 'operations:restore'],
  ['/operations/exports', 'operations:export'], ['/operations/retention', 'operations:retention'],
  ['/operations/demo', 'operations:demo_manage'], ['/operations/releases', 'operations:release'],
  ['/operations/inventory', 'operations:inventory'], ['/operations/configuration', 'operations:diagnostics'],
  ['/operations/jobs', 'operations:maintenance'],
  ['/operations/diagnostics', 'operations:diagnostics'], ['/operations/health', 'operations:diagnostics'],
  ['/operations', 'operations:view'],
  ['/admin/registrations', 'users:manage'], ['/admin/users', 'users:read'], ['/admin/roles', 'roles:read'], ['/security-audit', 'audit:read'],
  ['/dashboard', 'dashboard:view'], ['/targets', 'web:read'], ['/scans/new', 'web:run_scans'], ['/scans', 'web:read'], ['/reports', 'web:read'],
  ['/api-security/new', 'api:manage_assessments'], ['/api-security/assessments/', 'api:read'], ['/api-security', 'api:read'],
  ['/soc/simulator', 'soc:simulate'], ['/soc/imports', 'soc:import'], ['/soc/rules', 'soc:manage_rules'], ['/soc/blocklist', 'soc:manage_watchlist'], ['/soc', 'soc:read'],
  ['/document-threats/analyze', 'document:analyze'], ['/document-threats', 'document:read'],
  ['/phishing-defense/analyze', 'phishing:analyze'], ['/phishing-defense/watchlist', 'phishing:read'], ['/phishing-defense', 'phishing:read'],
  ['/correlation/cases', 'cases:read'], ['/correlation', 'correlation:read'],
  ['/governance', 'governance:read'], ['/search', 'search:use'], ['/notifications', 'notifications:read'],
  ['/threat-intelligence/indicators/new', 'threat_intel:manage'], ['/threat-intelligence/imports', 'threat_intel:import'],
  ['/threat-intelligence/reports', 'threat_intel:export'], ['/threat-intelligence', 'threat_intel:view'],
  ['/detections/rules/new', 'detections:manage'], ['/detections/import', 'detections:import'], ['/detections/reports', 'detections:export'], ['/detections', 'detections:view'],
  ['/settings', 'system:manage'], ['/profile', 'profile:manage'],
];

export function permissionForPath(path: string): string | undefined {
  if (/^\/detections\/rules\/\d+\/edit$/.test(path)) return 'detections:manage';
  return routePermissions.find(([prefix]) => path.startsWith(prefix))?.[1];
}
