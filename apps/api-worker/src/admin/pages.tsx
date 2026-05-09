import type { AuditLogRecord } from "@credtrail/db";
import { appPage, type AppPage } from "../ui/render-page";
import { formatIsoTimestamp } from "../utils/display-format";
import { AdminButton } from "./components";

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
    assets: ["institutionAdminCss"],
    variant: "admin",
    body: (
      <section class="ct-admin-content">
        <header class="ct-admin-page-header">
          <h1>Audit log viewer</h1>
          <p>Review recent tenant-scoped audit events for sensitive operations.</p>
        </header>
        <section class="ct-admin ct-stack">
          {input.submissionError === undefined ? null : (
            <p class="ct-admin__status" data-tone="error">
              {input.submissionError}
            </p>
          )}
          <article class="ct-admin__panel ct-stack">
            <form
              method="get"
              action="/admin/audit-logs"
              class="ct-admin__form ct-admin__form--inline ct-grid"
            >
              <input type="hidden" name="token" value={input.token} />
              <label>
                Tenant ID
                <input name="tenantId" type="text" required value={filterTenantId} />
              </label>
              <label>
                Action (optional exact match)
                <input name="action" type="text" value={filterAction} />
              </label>
              <label>
                Limit
                <input name="limit" type="number" min="1" max="200" value={filterLimit} />
              </label>
              <AdminButton type="submit">Load audit logs</AdminButton>
            </form>
          </article>
          <article class="ct-admin__panel ct-admin__panel--table ct-stack">
            <div class="ct-admin__table-wrap">
              <table class="ct-admin__table">
                <thead>
                  <tr>
                    <th>Occurred (UTC)</th>
                    <th>Action</th>
                    <th>Actor</th>
                    <th>Target</th>
                    <th>Metadata</th>
                  </tr>
                </thead>
                <tbody>
                  {input.logs.length === 0 ? (
                    <tr>
                      <td colspan={5} class="ct-admin__empty">
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
                          <td>{formatIsoTimestamp(log.occurredAt)}</td>
                          <td>{log.action}</td>
                          <td>{log.actorUserId ?? "system"}</td>
                          <td>
                            {log.targetType}:{log.targetId}
                          </td>
                          <td>
                            <details>
                              <summary>View metadata</summary>
                              <pre class="ct-admin__code-output">{metadataText}</pre>
                            </details>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </article>
        </section>
      </section>
    ),
  });
};
