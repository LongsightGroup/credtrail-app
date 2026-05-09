import type { AuditLogRecord } from "@credtrail/db";
import { appPage, type AppPage } from "../ui/render-page";
import { formatIsoTimestamp } from "../utils/display-format";
import {
  AdminButton,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminPageHeader,
  AdminPanel,
  AdminStatus,
  AdminTable,
} from "./components";

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
        <AdminPageHeader
          as="header"
          title="Audit log viewer"
          description="Review recent tenant-scoped audit events for sensitive operations."
        />
        <section class="ct-admin ct-stack">
          {input.submissionError === undefined ? null : (
            <AdminStatus tone="error">{input.submissionError}</AdminStatus>
          )}
          <AdminPanel>
            <AdminForm
              method="get"
              action="/admin/audit-logs"
              className="ct-admin__form ct-admin__form--inline ct-grid"
            >
              <input type="hidden" name="token" value={input.token} />
              <AdminField label="Tenant ID">
                <input name="tenantId" type="text" required value={filterTenantId} />
              </AdminField>
              <AdminField label="Action (optional exact match)">
                <input name="action" type="text" value={filterAction} />
              </AdminField>
              <AdminField label="Limit">
                <input name="limit" type="number" min="1" max="200" value={filterLimit} />
              </AdminField>
              <AdminButton type="submit">Load audit logs</AdminButton>
            </AdminForm>
          </AdminPanel>
          <AdminPanel variant="table">
            <AdminTable headers={["Occurred (UTC)", "Action", "Actor", "Target", "Metadata"]}>
              {input.logs.length === 0 ? (
                <AdminEmptyTableRow colSpan={5}>
                  {filterTenantId.trim().length === 0
                    ? "Enter a tenant ID to load audit logs."
                    : "No audit logs matched the current filters."}
                </AdminEmptyTableRow>
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
            </AdminTable>
          </AdminPanel>
        </section>
      </section>
    ),
  });
};
