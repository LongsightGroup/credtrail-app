import { formatIsoTimestamp } from "../../utils/display-format";
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
import { CtInput, CtSelect } from "../../ui/forms";
import { tenantOperationsManualIssuePath } from "../access-admin-helpers";
import type { AdminManualIssueReceipt } from "../manual-issue-flash";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | readonly HonoElement[];

interface RenderManualIssueSectionInput {
  tenantId: string;
  templateSelectOptions: HonoElement;
  listError?: string | null;
  listNotice?: string | null;
  receipt?: AdminManualIssueReceipt | null;
  pathwayHandoffId?: string | null;
}

export const renderManualIssueSection = (input: RenderManualIssueSectionInput): HonoElement => {
  const receipt = input.receipt ?? null;

  return (
    <AdminPanel id="manual-issue-panel">
      {input.listError !== null && input.listError !== undefined && input.listError.length > 0 ? (
        <AdminStatus data-tone="error">{input.listError}</AdminStatus>
      ) : input.listNotice !== null &&
        input.listNotice !== undefined &&
        input.listNotice.length > 0 ? (
        <>
          <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
          {receipt === null ? null : (
            <section aria-label="Issuance receipt" class="ct-stack">
              <h2>{receipt.badgeTitle}</h2>
              <p>
                <strong>Recipient:</strong> {receipt.recipientIdentity}
                <br />
                <strong>Issued:</strong> {formatIsoTimestamp(receipt.issuedAt)} UTC
              </p>
              <p>
                The credential is issued. You can open its public page or review its record and
                status.
              </p>
              <AdminActions>
                <AdminButtonLink href={receipt.recordPath} variant="primary">
                  View badge record
                </AdminButtonLink>
                <AdminButtonLink
                  href={receipt.publicBadgePath}
                  variant="secondary"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Open public badge
                </AdminButtonLink>
                <AdminButtonLink
                  href={tenantOperationsManualIssuePath(input.tenantId)}
                  variant="quiet"
                >
                  Issue another badge
                </AdminButtonLink>
              </AdminActions>
              <details>
                <summary>Technical details</summary>
                <AdminActions>
                  <AdminButtonLink
                    href={receipt.verificationPath}
                    variant="quiet"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Open verification JSON
                  </AdminButtonLink>
                  <AdminButtonLink
                    href={receipt.jsonLdPath}
                    variant="quiet"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Open JSON-LD
                  </AdminButtonLink>
                </AdminActions>
              </details>
            </section>
          )}
        </>
      ) : null}
      {receipt !== null && input.listNotice ? null : (
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
      )}
    </AdminPanel>
  );
};
