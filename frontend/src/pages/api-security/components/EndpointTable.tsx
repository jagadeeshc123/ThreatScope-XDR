import type { ApiEndpoint } from '../../../types';
import { ApiRiskBadge } from './ApiRiskBadge';
import { MethodBadge } from './MethodBadge';

export function EndpointTable({ endpoints }: { endpoints: ApiEndpoint[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[1200px] text-left text-sm">
        <thead className="border-b border-border text-xs font-semibold text-muted-foreground">
          <tr>
            <th className="py-3 pr-4">Method</th>
            <th className="py-3 pr-4">Path</th>
            <th className="py-3 pr-4">Auth</th>
            <th className="py-3 pr-4">Schemes</th>
            <th className="py-3 pr-4">Tags</th>
            <th className="py-3 pr-4">Request</th>
            <th className="py-3 pr-4">Response</th>
            <th className="py-3 pr-4">Deprecated</th>
            <th className="py-3 pr-4">Risk</th>
            <th className="py-3">Reasons</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {endpoints.map(endpoint => (
            <tr key={endpoint.id} className="align-top hover:bg-muted/30">
              <td className="py-4 pr-4"><MethodBadge method={endpoint.method} /></td>
              <td className="py-4 pr-4">
                <div className="break-all font-mono text-xs text-foreground">{endpoint.path}</div>
                <div className="mt-1 text-xs text-muted-foreground">{endpoint.summary || endpoint.operation_id || 'No summary documented'}</div>
                {endpoint.folder_path && <div className="mt-1 text-xs text-indigo-200">{endpoint.folder_path}</div>}
              </td>
              <td className="py-4 pr-4">{endpoint.auth_required ? 'Required' : 'Not declared'}</td>
              <td className="py-4 pr-4 text-xs text-muted-foreground">{endpoint.auth_schemes.join(', ') || '-'}</td>
              <td className="py-4 pr-4 text-xs text-muted-foreground">{endpoint.tags.join(', ') || '-'}</td>
              <td className="py-4 pr-4 text-xs text-muted-foreground">{endpoint.request_content_types.join(', ') || '-'}</td>
              <td className="py-4 pr-4 text-xs text-muted-foreground">{endpoint.response_content_types.join(', ') || '-'}</td>
              <td className="py-4 pr-4">{endpoint.deprecated ? 'Yes' : 'No'}</td>
              <td className="py-4 pr-4"><ApiRiskBadge risk={endpoint.preliminary_risk_level} /></td>
              <td className="py-4 text-xs leading-5 text-muted-foreground">{endpoint.preliminary_risk_reasons.join('; ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

