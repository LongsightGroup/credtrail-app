import type {
  TenantAuthPolicyRecord,
  TenantAuthProviderRecord,
  TenantBreakGlassAccountRecord,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  accessAuthenticationPageUrl,
  tenantAccessBreakGlassAccountCreatePath,
  tenantAccessBreakGlassAccountRevokePath,
  tenantAccessEnterpriseAuthPolicyPath,
  tenantAccessEnterpriseAuthProviderDeletePath,
  tenantAccessEnterpriseAuthProviderSavePath,
} from "../access-admin-helpers";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminCheckboxRow,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminMeta,
  AdminTable,
} from "../components";
import { CtInput, CtSelect, CtTextarea } from "../../ui/forms";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderEnterpriseAuthSectionInput {
  tenant: TenantRecord;
  enterpriseAuthPolicy?: TenantAuthPolicyRecord | null | undefined;
  enterpriseAuthProviders?: readonly TenantAuthProviderRecord[] | undefined;
  breakGlassAccounts?: readonly TenantBreakGlassAccountRecord[] | undefined;
  editProviderId?: string | null;
}

const formatJsonTextareaValue = (value: string): string => {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
};

export const renderEnterpriseAuthSection = (
  input: RenderEnterpriseAuthSectionInput,
): HonoElement | null => {
  if (input.tenant.planTier !== "enterprise") {
    return null;
  }

  const enterpriseAuthPolicy = input.enterpriseAuthPolicy ?? {
    tenantId: input.tenant.id,
    loginMode: "local" as const,
    breakGlassEnabled: false,
    localMfaRequired: false,
    defaultProviderId: null,
    enforceForRoles: "all_users" as const,
    createdAt: "",
    updatedAt: "",
  };
  const enterpriseAuthProviders = input.enterpriseAuthProviders ?? [];
  const breakGlassAccounts = input.breakGlassAccounts ?? [];
  const editingProvider =
    input.editProviderId === null || input.editProviderId === undefined
      ? null
      : (enterpriseAuthProviders.find((provider) => provider.id === input.editProviderId) ?? null);
  const enterpriseAuthProviderOptions = enterpriseAuthProviders.map((provider) => {
    return (
      <option value={provider.id} selected={enterpriseAuthPolicy.defaultProviderId === provider.id}>
        {provider.label}
      </option>
    );
  });
  const enterpriseAuthProviderRows =
    enterpriseAuthProviders.length === 0 ? (
      <AdminEmptyTableRow colSpan={6}>
        No OIDC enterprise providers configured yet.
      </AdminEmptyTableRow>
    ) : (
      enterpriseAuthProviders.map((provider) => {
        return (
          <tr>
            <td>
              <strong>{provider.label}</strong>
              <AdminMeta>{provider.id}</AdminMeta>
            </td>
            <td>{provider.protocol}</td>
            <td>{provider.isDefault ? "Default" : "Secondary"}</td>
            <td>{provider.enabled ? "Enabled" : "Disabled"}</td>
            <td>{formatIsoTimestamp(provider.updatedAt)}</td>
            <td>
              <AdminActions>
                <AdminButtonLink
                  href={accessAuthenticationPageUrl(input.tenant.id, { editProvider: provider.id })}
                  size="tiny"
                  variant="secondary"
                >
                  Edit
                </AdminButtonLink>
                <AdminForm
                  method="post"
                  action={tenantAccessEnterpriseAuthProviderDeletePath(input.tenant.id)}
                  className="ct-admin__inline-form"
                  dataAttributes={{
                    "data-confirm-message": `Delete ${provider.label}?`,
                  }}
                >
                  <CtInput type="hidden" name="providerId" value={provider.id} />
                  <AdminButton type="submit" size="tiny" variant="danger">
                    Delete
                  </AdminButton>
                </AdminForm>
              </AdminActions>
            </td>
          </tr>
        );
      })
    );

  return (
    <article id="enterprise-auth-panel" class="ct-admin__panel ct-stack">
      <h2>Enterprise Auth</h2>
      <p>Configure hosted OIDC providers for institution sign-in.</p>
      <AdminForm
        id="enterprise-auth-policy-form"
        method="post"
        action={tenantAccessEnterpriseAuthPolicyPath(input.tenant.id)}
      >
        <AdminField label="Login mode">
          <CtSelect name="loginMode" required>
            <option value="local" selected={enterpriseAuthPolicy.loginMode === "local"}>
              Local only
            </option>
            <option value="hybrid" selected={enterpriseAuthPolicy.loginMode === "hybrid"}>
              Hybrid
            </option>
            <option
              value="sso_required"
              selected={enterpriseAuthPolicy.loginMode === "sso_required"}
            >
              SSO required
            </option>
          </CtSelect>
        </AdminField>
        <AdminField label="Default provider">
          <CtSelect name="defaultProviderId">
            <option value="">No default provider</option>
            {enterpriseAuthProviderOptions}
          </CtSelect>
        </AdminField>
        <p class="ct-admin__hint">
          SSO enforcement applies to the tenant login experience. Role-specific enforcement is not
          configurable in the hosted runtime.
        </p>
        <AdminCheckboxRow
          name="breakGlassEnabled"
          label="Break-glass local access enabled"
          checked={enterpriseAuthPolicy.breakGlassEnabled}
        />
        <AdminCheckboxRow
          name="localMfaRequired"
          label="Require MFA for local access"
          checked={enterpriseAuthPolicy.localMfaRequired}
        />
        <AdminButton type="submit">Save auth policy</AdminButton>
      </AdminForm>
      <AdminForm
        id="enterprise-auth-provider-form"
        method="post"
        action={tenantAccessEnterpriseAuthProviderSavePath(input.tenant.id)}
      >
        <CtInput type="hidden" name="providerId" value={editingProvider?.id ?? ""} />
        <CtInput type="hidden" name="protocol" value="oidc" />
        <p class="ct-admin__hint">
          {editingProvider === null
            ? "Add a hosted OIDC provider here."
            : `Editing ${editingProvider.label}. Save changes or clear the form to add a new provider.`}
        </p>
        <AdminField label="OIDC provider label">
          <CtInput
            name="label"
            type="text"
            required
            placeholder="Campus OIDC"
            value={editingProvider?.label ?? ""}
          />
        </AdminField>
        <AdminField label="OIDC discovery or connection JSON">
          <CtTextarea
            id="enterprise-auth-provider-config-json"
            name="configJson"
            rows={8}
            required
            variant="code"
            placeholder='{"issuer":"https://idp.example.edu","clientId":"credtrail"}'
            value={formatJsonTextareaValue(editingProvider?.configJson ?? "")}
          />
        </AdminField>
        <AdminCheckboxRow
          name="enabled"
          label="Provider enabled"
          checked={editingProvider === null ? true : editingProvider.enabled}
        />
        <AdminCheckboxRow
          name="isDefault"
          label="Set as default provider"
          checked={editingProvider?.isDefault === true}
        />
        <AdminActions>
          <AdminButton type="submit">
            {editingProvider === null ? "Save provider" : "Update provider"}
          </AdminButton>
          {editingProvider === null ? null : (
            <AdminButtonLink
              href={accessAuthenticationPageUrl(input.tenant.id)}
              variant="secondary"
            >
              Clear form
            </AdminButtonLink>
          )}
        </AdminActions>
      </AdminForm>
      <AdminTable
        headers={["Provider", "Protocol", "Role", "Status", "Updated", "Actions"]}
        tbodyId="enterprise-auth-provider-body"
      >
        {enterpriseAuthProviderRows}
      </AdminTable>
      <section class="ct-stack" aria-labelledby="break-glass-accounts-title">
        <h3 id="break-glass-accounts-title">Break-glass local accounts</h3>
        <p>
          Limit local fallback access to explicit accounts only. CredTrail emails setup links and
          records recent fallback usage.
        </p>
        <AdminForm
          id="break-glass-account-form"
          method="post"
          action={tenantAccessBreakGlassAccountCreatePath(input.tenant.id)}
        >
          <AdminField label="Institution email">
            <CtInput name="email" type="email" required placeholder="admin@institution.edu" />
          </AdminField>
          <AdminCheckboxRow
            name="sendEnrollmentEmail"
            label="Email setup or password-reset link now"
            checked
          />
          <AdminButton type="submit">Add break-glass account</AdminButton>
        </AdminForm>
        <AdminTable
          headers={["Email", "Local status", "Last used", "Enrollment email", "Actions"]}
          tbodyId="break-glass-account-body"
        >
          {breakGlassAccounts.length === 0 ? (
            <AdminEmptyTableRow colSpan={5}>
              No break-glass accounts configured yet.
            </AdminEmptyTableRow>
          ) : (
            breakGlassAccounts.map((account) => {
              const localStatus = account.twoFactorEnabled
                ? "MFA ready"
                : account.localCredentialEnabled
                  ? "Password ready"
                  : "Setup pending";

              return (
                <tr>
                  <td>
                    <strong>{account.email}</strong>
                    <AdminMeta>{account.userId}</AdminMeta>
                  </td>
                  <td>{localStatus}</td>
                  <td>
                    {account.lastUsedAt === null ? "Never" : formatIsoTimestamp(account.lastUsedAt)}
                  </td>
                  <td>
                    {account.lastEnrollmentEmailSentAt === null
                      ? "Not sent"
                      : formatIsoTimestamp(account.lastEnrollmentEmailSentAt)}
                  </td>
                  <td>
                    <AdminForm
                      method="post"
                      action={tenantAccessBreakGlassAccountRevokePath(input.tenant.id)}
                      className="ct-admin__inline-form"
                      dataAttributes={{
                        "data-confirm-message": `Revoke break-glass access for ${account.email}?`,
                      }}
                    >
                      <CtInput type="hidden" name="userId" value={account.userId} />
                      <AdminButton type="submit" size="tiny" variant="danger">
                        Revoke
                      </AdminButton>
                    </AdminForm>
                  </td>
                </tr>
              );
            })
          )}
        </AdminTable>
      </section>
      {enterpriseAuthProviders.length > 0 ? (
        <details class="ct-admin__panel ct-admin__panel--nested">
          <summary>Selected provider config preview</summary>
          <pre class="ct-admin__code-output">
            {formatJsonTextareaValue(enterpriseAuthProviders[0]?.configJson ?? "{}")}
          </pre>
        </details>
      ) : null}
    </article>
  );
};
