/** Server-rendered API key table row fragment for the admin UI. */
import type { TenantApiKeyRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { tenantApiKeyAdminRevokePath } from "./api-key-admin-helpers";
import { formatIsoTimestamp } from "../utils/display-format";
import { AdminButton, AdminForm } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const formatTenantApiKeyScopesSummary = (scopesJson: string): string => {
  try {
    const parsed = JSON.parse(scopesJson) as unknown;

    if (!Array.isArray(parsed)) {
      return scopesJson;
    }

    const scopes = parsed
      .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
      .filter((entry) => entry.length > 0);

    return scopes.length === 0 ? "none" : scopes.join(", ");
  } catch {
    return scopesJson;
  }
};

export const TenantApiKeyAdminTableRow = ({
  tenantId,
  apiKey,
}: {
  tenantId: string;
  apiKey: TenantApiKeyRecord;
}): HonoElement => {
  return (
    <tr data-api-key-id={apiKey.id}>
      <td>{apiKey.label}</td>
      <td>{apiKey.keyPrefix}</td>
      <td>{formatTenantApiKeyScopesSummary(apiKey.scopesJson)}</td>
      <td>{apiKey.expiresAt === null ? "Never" : formatIsoTimestamp(apiKey.expiresAt)}</td>
      <td>
        <AdminForm
          method="post"
          action={tenantApiKeyAdminRevokePath(tenantId, apiKey.id)}
          className="ct-admin__inline-form"
          dataAttributes={{
            "data-api-key-revoke-form": "true",
            "data-api-key-label": apiKey.label,
          }}
        >
          <AdminButton type="submit" variant="danger">
            Revoke
          </AdminButton>
        </AdminForm>
      </td>
    </tr>
  );
};

