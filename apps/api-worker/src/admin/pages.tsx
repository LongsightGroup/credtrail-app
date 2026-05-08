import type { AuditLogRecord } from "@credtrail/db";
import { appPage, type AppPage } from "../ui/render-page";
import { formatIsoTimestamp } from "../utils/display-format";

export interface AuditLogAdminPageFilterState {
  tenantId?: string;
  action?: string;
  limit?: number;
}

const metadataSummaryText = (metadataJson: string | null): string => {
  if (metadataJson === null) {
    return "No metadata";
  }

  try {
    const parsed = JSON.parse(metadataJson) as unknown;
    return JSON.stringify(parsed, null, 2);
  } catch {
    return metadataJson;
  }
};

export const auditLogAdminPage = (input: {
  token: string;
  logs: readonly AuditLogRecord[];
  filterState: AuditLogAdminPageFilterState;
  submissionError?: string;
}): AppPage => {
  const filterTenantId = input.filterState.tenantId ?? "";
  const filterAction = input.filterState.action ?? "";
  const filterLimit = String(input.filterState.limit ?? 100);

  return appPage({
    title: "Audit Logs | CredTrail",
    body: (
      <section style="display:grid;gap:1rem;max-width:72rem;">
        <h1 style="margin:0;">Audit log viewer</h1>
        <p style="margin:0;color:#334155;">
          Review recent tenant-scoped audit events for sensitive operations.
        </p>
        {input.submissionError === undefined ? null : (
          <p style="margin:0;padding:0.75rem;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;">
            {input.submissionError}
          </p>
        )}
        <form
          method="get"
          action="/admin/audit-logs"
          style="display:grid;gap:0.75rem;padding:1rem;border:1px solid #cbd5e1;border-radius:0.5rem;"
        >
          <input type="hidden" name="token" value={input.token} />
          <label style="display:grid;gap:0.35rem;">
            <span>Tenant ID</span>
            <input name="tenantId" type="text" required value={filterTenantId} />
          </label>
          <label style="display:grid;gap:0.35rem;">
            <span>Action (optional exact match)</span>
            <input name="action" type="text" value={filterAction} />
          </label>
          <label style="display:grid;gap:0.35rem;max-width:12rem;">
            <span>Limit</span>
            <input name="limit" type="number" min="1" max="200" value={filterLimit} />
          </label>
          <div>
            <button type="submit">Load audit logs</button>
          </div>
        </form>
        <div style="overflow:auto;">
          <table style="width:100%;border-collapse:collapse;">
            <thead>
              <tr>
                <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">
                  Occurred (UTC)
                </th>
                <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">
                  Action
                </th>
                <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">
                  Actor
                </th>
                <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">
                  Target
                </th>
                <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">
                  Metadata
                </th>
              </tr>
            </thead>
            <tbody>
              {input.logs.length === 0 ? (
                <tr>
                  <td colspan={5} style="padding:0.75rem;">
                    {filterTenantId.trim().length === 0
                      ? "Enter a tenant ID to load audit logs."
                      : "No audit logs matched the current filters."}
                  </td>
                </tr>
              ) : (
                input.logs.map((log) => {
                  const metadataText = metadataSummaryText(log.metadataJson);

                  return (
                    <tr key={`${log.occurredAt}:${log.action}:${log.targetId}`}>
                      <td style="padding:0.5rem;vertical-align:top;white-space:nowrap;">
                        {formatIsoTimestamp(log.occurredAt)}
                      </td>
                      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">
                        {log.action}
                      </td>
                      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">
                        {log.actorUserId ?? "system"}
                      </td>
                      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">
                        {log.targetType}:{log.targetId}
                      </td>
                      <td style="padding:0.5rem;vertical-align:top;">
                        <details>
                          <summary>View metadata</summary>
                          <pre style="margin:0.5rem 0 0;white-space:pre-wrap;word-break:break-word;">
                            {metadataText}
                          </pre>
                        </details>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    ),
  });
};
