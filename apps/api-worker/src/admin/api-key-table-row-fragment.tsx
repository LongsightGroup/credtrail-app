/** Server-rendered API key table row fragment for the admin UI. */
import type { TenantApiKeyRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import { AdminButton } from "./components";

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

export const tenantApiKeyRevokePath = (tenantId: string, apiKeyId: string): string => {
  return `/v1/tenants/${encodeURIComponent(tenantId)}/api-keys/${encodeURIComponent(
    apiKeyId,
  )}/revoke`;
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
        <AdminButton
          type="button"
          variant="danger"
          dataAttributes={{
            "data-revoke-api-key-path": tenantApiKeyRevokePath(tenantId, apiKey.id),
            "data-api-key-label": apiKey.label,
          }}
        >
          Revoke
        </AdminButton>
      </td>
    </tr>
  );
};

export const renderTenantApiKeyAdminTableRowToString = (input: {
  tenantId: string;
  apiKey: TenantApiKeyRecord;
}): string => {
  const renderable = (<TenantApiKeyAdminTableRow {...input} />) as { toString(): string };

  return renderable.toString();
};
