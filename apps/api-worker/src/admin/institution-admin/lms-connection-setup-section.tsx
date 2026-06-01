import type { HtmlEscapedString } from "hono/utils/html";
import { AdminButton, AdminField, AdminForm, AdminPanel, AdminStatus } from "../components";
import { tenantLmsConnectionAdminSavePath } from "../lms-connection-admin-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export interface LmsConnectionFormValues {
  connectionId: string;
  displayName: string;
  providerKind: "canvas" | "sakai";
  apiBaseUrl: string;
  ltiIssuer: string;
  ltiClientId: string;
  ltiDeploymentId: string;
}

interface RenderLmsConnectionSetupSectionInput {
  tenantId: string;
  formValues: LmsConnectionFormValues;
  listError?: string | null;
  listNotice?: string | null;
}

export const renderLmsConnectionSetupSection = (
  input: RenderLmsConnectionSetupSectionInput,
): HonoElement => {
  const isUpdate = input.formValues.connectionId.length > 0;

  return (
    <AdminPanel id="lms-connection-setup-panel" className="ct-stack">
      {input.listError !== null && input.listError !== undefined && input.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.listError}</AdminStatus>
      ) : input.listNotice !== null &&
        input.listNotice !== undefined &&
        input.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
      ) : null}
      <AdminForm
        id="lms-connection-form"
        method="post"
        action={tenantLmsConnectionAdminSavePath(input.tenantId)}
        className="ct-admin__form ct-admin__setup-form ct-stack"
      >
        <input name="connectionId" type="hidden" value={input.formValues.connectionId} />
        <AdminField label="Connection name">
          <input
            name="displayName"
            type="text"
            required
            placeholder="TrySakai test server"
            value={input.formValues.displayName}
          />
        </AdminField>
        <AdminField label="Provider">
          <select name="providerKind" required>
            <option value="canvas" selected={input.formValues.providerKind !== "sakai"}>
              Canvas
            </option>
            <option value="sakai" selected={input.formValues.providerKind === "sakai"}>
              Sakai
            </option>
          </select>
        </AdminField>
        <AdminField label="API/server URL">
          <input
            name="apiBaseUrl"
            type="url"
            required
            placeholder="https://lms.example.edu"
            value={input.formValues.apiBaseUrl}
          />
        </AdminField>
        <AdminField label="Credential or session value">
          <input
            name="accessToken"
            type="password"
            autocomplete="off"
            placeholder={
              isUpdate
                ? "Leave blank to keep existing credential"
                : input.formValues.providerKind === "sakai"
                  ? "Paste Sakai SAKAIID session value"
                  : "Paste Canvas access token"
            }
          />
        </AdminField>
        <details class="ct-admin__advanced-tools">
          <summary>
            <span>Advanced OAuth and LTI metadata</span>
            <small>
              Add refresh credentials or LTI identifiers only when this connection needs them.
            </small>
          </summary>
          <div class="ct-admin__advanced-tools-body ct-grid">
            <AdminField label="Refresh token (optional)">
              <input name="refreshToken" type="password" autocomplete="off" />
            </AdminField>
            <AdminField label="Authorization endpoint (optional)">
              <input
                name="authorizationEndpoint"
                type="url"
                placeholder="https://lms.example.edu/login/oauth2/auth"
              />
            </AdminField>
            <AdminField label="Token endpoint (optional)">
              <input
                name="tokenEndpoint"
                type="url"
                placeholder="https://lms.example.edu/login/oauth2/token"
              />
            </AdminField>
            <AdminField label="OAuth client ID (optional)">
              <input name="clientId" type="text" autocomplete="off" />
            </AdminField>
            <AdminField label="OAuth client secret (optional)">
              <input name="clientSecret" type="password" autocomplete="off" />
            </AdminField>
            <AdminField label="LTI issuer (optional)">
              <input name="ltiIssuer" type="url" value={input.formValues.ltiIssuer} />
            </AdminField>
            <AdminField label="LTI client ID (optional)">
              <input name="ltiClientId" type="text" value={input.formValues.ltiClientId} />
            </AdminField>
            <AdminField label="LTI deployment ID (optional)">
              <input name="ltiDeploymentId" type="text" value={input.formValues.ltiDeploymentId} />
            </AdminField>
          </div>
        </details>
        <AdminButton type="submit">
          {isUpdate ? "Save connection changes" : "Save and connect gradebook"}
        </AdminButton>
      </AdminForm>
      {isUpdate ? (
        <p class="ct-admin__hint">
          Leave credential fields blank to keep saved secrets. Connection ID:{" "}
          <code>{input.formValues.connectionId}</code>
        </p>
      ) : null}
    </AdminPanel>
  );
};

export const emptyLmsConnectionFormValues = (): LmsConnectionFormValues => {
  return {
    connectionId: "",
    displayName: "",
    providerKind: "canvas",
    apiBaseUrl: "",
    ltiIssuer: "",
    ltiClientId: "",
    ltiDeploymentId: "",
  };
};

export const lmsConnectionFormValuesFromRecord = (connection: {
  id: string;
  displayName: string;
  providerKind: "canvas" | "sakai";
  apiBaseUrl: string;
  ltiIssuer: string | null;
  ltiClientId: string | null;
  ltiDeploymentId: string | null;
}): LmsConnectionFormValues => {
  return {
    connectionId: connection.id,
    displayName: connection.displayName,
    providerKind: connection.providerKind,
    apiBaseUrl: connection.apiBaseUrl,
    ltiIssuer: connection.ltiIssuer ?? "",
    ltiClientId: connection.ltiClientId ?? "",
    ltiDeploymentId: connection.ltiDeploymentId ?? "",
  };
};
