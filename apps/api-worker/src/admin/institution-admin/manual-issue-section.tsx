import type { HtmlEscapedString } from "hono/utils/html";
import { AdminButton, AdminField, AdminForm, AdminPanel, AdminStatus } from "../components";
import { CtInput, CtSelect } from "../../ui/forms";
import { tenantOperationsManualIssuePath } from "../access-admin-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | readonly HonoElement[];

interface RenderManualIssueSectionInput {
  tenantId: string;
  templateSelectOptions: HonoElement;
  listError?: string | null;
  listNotice?: string | null;
  pathwayHandoffId?: string | null;
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
        {input.pathwayHandoffId === null || input.pathwayHandoffId === undefined ? null : (
          <>
            <CtInput
              name="learnerPathwayCompletionHandoffId"
              type="hidden"
              value={input.pathwayHandoffId}
            />
            <AdminStatus data-tone="info">
              This issuance will complete the selected governed learner pathway.
            </AdminStatus>
          </>
        )}
        <AdminField label="Badge template">
          <CtSelect name="badgeTemplateId" required>
            {input.templateSelectOptions}
          </CtSelect>
        </AdminField>
        <AdminField label="Recipient email">
          <CtInput
            name="recipientIdentity"
            type="email"
            required
            placeholder="recipient@example.com"
          />
        </AdminField>
        <AdminButton type="submit">Issue badge</AdminButton>
      </AdminForm>
    </AdminPanel>
  );
};
