import type { ManualIssueSelection } from "../manual-issue-selection";
import { badgeTemplateAdminEditorHref } from "../badge-template-admin-helpers";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminButtonLink,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
} from "../components";
import { CtInput, CtSelect } from "../../ui/forms";
import { tenantOperationsManualIssuePath } from "../access-admin-helpers";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString> | readonly HonoElement[];

interface RenderManualIssueSectionInput {
  correction?: import("../manual-issue-correction").ManualIssueCorrection | undefined;
  hasReadyTemplates: boolean;
  selection?: ManualIssueSelection;
  tenantId: string;
  templateSelectOptions: HonoElement;
  listError?: string | null;
  listNotice?: string | null;
  pathwayHandoffId?: string | null;
}

export const renderManualIssueSection = (input: RenderManualIssueSectionInput): HonoElement => {
  const resolvedSelection = input.selection ?? { kind: "choose" };
  const selection =
    input.correction !== undefined && resolvedSelection.kind === "blocked"
      ? { kind: "choose" as const }
      : resolvedSelection;
  if (selection.kind === "choose" && !input.hasReadyTemplates)
    return (
      <AdminPanel>
        <p>No badges are ready to issue. Prepare a badge first.</p>
        <AdminButtonLink
          href={`/tenants/${encodeURIComponent(input.tenantId)}/admin/rules/templates`}
        >
          Prepare a badge
        </AdminButtonLink>
      </AdminPanel>
    );
  if (selection.kind === "blocked")
    return (
      <AdminPanel>
        <AdminStatus data-tone="error">{selection.message}</AdminStatus>
        {selection.template === null ? null : (
          <AdminButtonLink
            href={badgeTemplateAdminEditorHref(input.tenantId, selection.template.id)}
          >
            Prepare badge
          </AdminButtonLink>
        )}
        <AdminButtonLink href={tenantOperationsManualIssuePath(input.tenantId)} variant="secondary">
          Choose a different badge
        </AdminButtonLink>
      </AdminPanel>
    );
  return (
    <AdminPanel id="manual-issue-panel">
      {input.listError !== null && input.listError !== undefined && input.listError.length > 0 ? (
        <p id="manual-issue-error" role="alert" tabindex={-1} class="ct-field__error">
          {input.listError}
        </p>
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
        {selection.kind === "ready" ? (
          <section aria-label="Selected badge" class="ct-stack">
            {selection.template.imageUri === null ? null : (
              <img
                src={selection.template.imageUri}
                alt={`${selection.template.title} artwork`}
                width={96}
                height={96}
                class="ct-admin__template-image"
              />
            )}
            <h2>{selection.template.title}</h2>
            <CtInput name="badgeTemplateId" type="hidden" value={selection.template.id} />
            {input.pathwayHandoffId ? null : (
              <AdminButtonLink
                href={tenantOperationsManualIssuePath(input.tenantId)}
                variant="quiet"
              >
                Change badge
              </AdminButtonLink>
            )}
          </section>
        ) : (
          <AdminField label="Badge template">
            <CtSelect name="badgeTemplateId" required>
              {input.templateSelectOptions}
            </CtSelect>
          </AdminField>
        )}
        <AdminField label="Recipient email">
          <CtInput
            name="recipientIdentity"
            type="email"
            value={input.correction?.recipientIdentity}
            describedBy={input.correction ? "manual-issue-error" : undefined}
            required
            placeholder="recipient@example.com"
          />
        </AdminField>
        <p
          id="manual-issue-consequence"
          data-badge-title={selection.kind === "ready" ? selection.template.title : ""}
        >
          This creates a credential with a public verification page for the selected badge and
          recipient.
        </p>
        <AdminButton type="submit">Issue badge</AdminButton>
      </AdminForm>
    </AdminPanel>
  );
};
