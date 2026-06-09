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
  const supportedEnterpriseAuthProviders = enterpriseAuthProviders.filter(
    (provider) => provider.protocol === "oidc",
  );
  const legacySamlProviders = enterpriseAuthProviders.filter(
    (provider) => provider.protocol === "saml",
  );
  const legacyDefaultProvider = legacySamlProviders.find(
    (provider) => provider.id === enterpriseAuthPolicy.defaultProviderId,
  );
  const breakGlassAccounts = input.breakGlassAccounts ?? [];
  const editingProvider =
    input.editProviderId === null || input.editProviderId === undefined
      ? null
      : (supportedEnterpriseAuthProviders.find(
          (provider) => provider.id === input.editProviderId,
        ) ?? null);
  const enterpriseAuthProviderOptions = supportedEnterpriseAuthProviders.map((provider) => {
    return (
      <option value={provider.id} selected={enterpriseAuthPolicy.defaultProviderId === provider.id}>
        {provider.label}
      </option>
    );
  });
  const enterpriseAuthProviderRows =
    supportedEnterpriseAuthProviders.length === 0 ? (
      <AdminEmptyTableRow colSpan={6}>
        No OIDC enterprise providers configured yet.
      </AdminEmptyTableRow>
    ) : (
      supportedEnterpriseAuthProviders.map((provider) => {
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
                  <input type="hidden" name="providerId" value={provider.id} />
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
  const legacySamlRows =
    legacySamlProviders.length === 0 ? (
      <AdminEmptyTableRow colSpan={5}>
        No legacy SAML compatibility entries detected.
      </AdminEmptyTableRow>
    ) : (
      legacySamlProviders.map((provider) => {
        return (
          <tr>
            <td>
              <strong>{provider.label}</strong>
              <AdminMeta>{provider.id}</AdminMeta>
            </td>
            <td>{provider.isDefault ? "Default" : "Secondary"}</td>
            <td>{provider.enabled ? "Enabled" : "Disabled"}</td>
            <td>{formatIsoTimestamp(provider.updatedAt)}</td>
            <td>
              <AdminForm
                method="post"
                action={tenantAccessEnterpriseAuthProviderDeletePath(input.tenant.id)}
                className="ct-admin__inline-form"
                dataAttributes={{
                  "data-confirm-message": `Delete legacy SAML entry “${provider.label}”?`,
                }}
              >
                <input type="hidden" name="providerId" value={provider.id} />
                <AdminButton type="submit" size="tiny" variant="danger">
                  Delete
                </AdminButton>
              </AdminForm>
            </td>
          </tr>
        );
      })
    );

  return (
    <article id="enterprise-auth-panel" class="ct-admin__panel ct-stack">
      <h2>Enterprise Auth</h2>
      <p>
        Hosted enterprise sign-in supports OIDC providers. Legacy SAML compatibility stays visible
        for cleanup only.
      </p>
      <AdminForm
        id="enterprise-auth-policy-form"
        method="post"
        action={tenantAccessEnterpriseAuthPolicyPath(input.tenant.id)}
      >
        <AdminField label="Login mode">
          <select name="loginMode" required>
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
          </select>
        </AdminField>
        <AdminField label="Default provider">
          <select name="defaultProviderId">
            <option value="">No default provider</option>
            {enterpriseAuthProviderOptions}
          </select>
        </AdminField>
        <p class="ct-admin__hint">
          SSO enforcement applies to the tenant login experience. Role-specific enforcement is not
          configurable in the hosted runtime.
        </p>
        {legacyDefaultProvider === undefined ? null : (
          <p class="ct-admin__hint">
            This tenant still references <strong>{legacyDefaultProvider.label}</strong> as a legacy
            default. Choose an OIDC provider before requiring institution sign-in.
          </p>
        )}
        <AdminCheckboxRow>
          <input
            name="breakGlassEnabled"
            type="checkbox"
            checked={enterpriseAuthPolicy.breakGlassEnabled}
          />
          Break-glass local access enabled
        </AdminCheckboxRow>
        <AdminCheckboxRow>
          <input
            name="localMfaRequired"
            type="checkbox"
            checked={enterpriseAuthPolicy.localMfaRequired}
          />
          Require MFA for local access
        </AdminCheckboxRow>
        <AdminButton type="submit">Save auth policy</AdminButton>
      </AdminForm>
      <AdminForm
        id="enterprise-auth-provider-form"
        method="post"
        action={tenantAccessEnterpriseAuthProviderSavePath(input.tenant.id)}
      >
        <input type="hidden" name="providerId" value={editingProvider?.id ?? ""} />
        <input type="hidden" name="protocol" value="oidc" />
        <p class="ct-admin__hint">
          {editingProvider === null
            ? "Add a hosted OIDC provider here. Use a new OIDC connection instead of modifying legacy SAML settings."
            : `Editing ${editingProvider.label}. Save changes or clear the form to add a new provider.`}
        </p>
        <AdminField label="OIDC provider label">
          <input
            name="label"
            type="text"
            required
            placeholder="Campus OIDC"
            value={editingProvider?.label ?? ""}
          />
        </AdminField>
        <AdminField label="OIDC discovery or connection JSON">
          <textarea
            id="enterprise-auth-provider-config-json"
            name="configJson"
            rows={8}
            required
            spellcheck={false}
            placeholder='{"issuer":"https://idp.example.edu","clientId":"credtrail"}'
          >
            {formatJsonTextareaValue(editingProvider?.configJson ?? "")}
          </textarea>
        </AdminField>
        <AdminCheckboxRow>
          <input
            name="enabled"
            type="checkbox"
            checked={editingProvider === null ? true : editingProvider.enabled}
          />
          Provider enabled
        </AdminCheckboxRow>
        <AdminCheckboxRow>
          <input name="isDefault" type="checkbox" checked={editingProvider?.isDefault === true} />
          Set as default provider
        </AdminCheckboxRow>
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
      {legacySamlProviders.length === 0 ? null : (
        <section class="ct-stack" aria-labelledby="legacy-saml-title">
          <h3 id="legacy-saml-title">Legacy SAML compatibility</h3>
          <p>
            These entries remain visible so you can audit or remove older SAML setup after an OIDC
            cutover. They are not editable from the hosted provider workflow.
          </p>
          <AdminTable headers={["Legacy entry", "Role", "Status", "Updated", "Actions"]}>
            {legacySamlRows}
          </AdminTable>
        </section>
      )}
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
            <input name="email" type="email" required placeholder="admin@institution.edu" />
          </AdminField>
          <AdminCheckboxRow>
            <input name="sendEnrollmentEmail" type="checkbox" checked />
            Email setup or password-reset link now
          </AdminCheckboxRow>
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
                      <input type="hidden" name="userId" value={account.userId} />
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
