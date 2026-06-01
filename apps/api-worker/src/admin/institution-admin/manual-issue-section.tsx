import type { HtmlEscapedString } from "hono/utils/html";
import { AdminButton, AdminField, AdminForm, AdminPanel, AdminStatus } from "../components";
import { tenantOperationsManualIssuePath } from "../access-admin-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | readonly HonoElement[];

interface RenderManualIssueSectionInput {
  tenantId: string;
  templateSelectOptions: HonoElement;
  listError?: string | null;
  listNotice?: string | null;
}

export const renderManualIssueSection = (input: RenderManualIssueSectionInput): HonoElement => {
  return (
    <AdminPanel id="manual-issue-panel">
      {input.listError !== null && input.listError !== undefined && input.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.listError}</AdminStatus>
      ) : input.listNotice !== null &&
        input.listNotice !== undefined &&
        input.listNotice.length > 0 ? (
        <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
      ) : null}
      <AdminForm
        id="manual-issue-form"
        method="post"
        action={tenantOperationsManualIssuePath(input.tenantId)}
        className="ct-admin__form ct-admin__setup-form ct-stack"
      >
        <AdminField label="Badge template">
          <select name="badgeTemplateId" required>
            {input.templateSelectOptions}
          </select>
        </AdminField>
        <AdminField label="Recipient email">
          <input name="recipientIdentity" type="email" required placeholder="csev@umich.edu" />
        </AdminField>
        <AdminButton type="submit">Issue badge</AdminButton>
      </AdminForm>
    </AdminPanel>
  );
};
