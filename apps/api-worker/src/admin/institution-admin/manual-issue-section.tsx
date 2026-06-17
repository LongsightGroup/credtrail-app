import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
} from "../components";
import { tenantOperationsManualIssuePath } from "../access-admin-helpers";
import type { AdminManualIssueSuccessLinks } from "../manual-issue-flash";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | readonly HonoElement[];

interface RenderManualIssueSectionInput {
  tenantId: string;
  templateSelectOptions: HonoElement;
  listError?: string | null;
  listNotice?: string | null;
  successLinks?: AdminManualIssueSuccessLinks | null;
}

export const renderManualIssueSection = (input: RenderManualIssueSectionInput): HonoElement => {
  const successLinks = input.successLinks ?? null;

  return (
    <AdminPanel id="manual-issue-panel">
      {input.listError !== null && input.listError !== undefined && input.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.listError}</AdminStatus>
      ) : input.listNotice !== null &&
        input.listNotice !== undefined &&
        input.listNotice.length > 0 ? (
        <>
          <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
          {successLinks === null ? null : (
            <AdminActions>
              <AdminButtonLink
                href={successLinks.publicBadgePath}
                variant="primary"
                target="_blank"
                rel="noopener noreferrer"
              >
                Open public badge
              </AdminButtonLink>
              <AdminButtonLink
                href={successLinks.verificationPath}
                variant="secondary"
                target="_blank"
                rel="noopener noreferrer"
              >
                Open verification JSON
              </AdminButtonLink>
              <AdminButtonLink
                href={successLinks.jsonLdPath}
                variant="ghost"
                target="_blank"
                rel="noopener noreferrer"
              >
                Open JSON-LD
              </AdminButtonLink>
            </AdminActions>
          )}
        </>
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
          <input
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
