import type {
  BadgeIssuanceRuleBuilderDraftRecord,
  BadgeTemplateRecord,
  TenantLmsConnectionRecord,
} from "@credtrail/db";
import { parseBadgeIssuanceRuleBuilderDraftJson } from "@credtrail/validation";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../../utils/display-format";
import {
  tenantBadgeRuleBuilderDraftDeleteAdminPath,
  tenantBadgeRuleBuilderDraftEditAdminPath,
} from "../access-admin-helpers";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminForm,
  AdminMeta,
  AdminStatusPill,
} from "../components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface RenderBadgeRuleBuilderDraftRowsInput {
  readonly tenantId: string;
  readonly drafts: readonly BadgeIssuanceRuleBuilderDraftRecord[];
  readonly badgeTemplates: readonly BadgeTemplateRecord[];
  readonly lmsConnections: readonly TenantLmsConnectionRecord[];
}

/** Renders unfinished new-rule drafts owned by the current administrator. */
export const renderBadgeRuleBuilderDraftRows = (
  input: RenderBadgeRuleBuilderDraftRowsInput,
): HonoElement[] => {
  const templateById = new Map(input.badgeTemplates.map((template) => [template.id, template]));
  const lmsConnectionById = new Map(
    input.lmsConnections.map((connection) => [connection.id, connection]),
  );

  return input.drafts.map((draft) => {
    const payload = parseBadgeIssuanceRuleBuilderDraftJson(draft.draftJson);
    const name = payload?.name?.trim() || "Untitled rule";
    const badgeTemplateId = payload?.badgeTemplateId?.trim() ?? "";
    const lmsConnectionId = payload?.lmsConnectionId?.trim() ?? "";
    const templateTitle =
      badgeTemplateId.length === 0
        ? "Not selected"
        : (templateById.get(badgeTemplateId)?.title ?? badgeTemplateId);
    const lmsLabel =
      lmsConnectionId.length === 0
        ? "Not selected"
        : (lmsConnectionById.get(lmsConnectionId)?.displayName ?? lmsConnectionId);
    const editPath = tenantBadgeRuleBuilderDraftEditAdminPath(input.tenantId, draft.id);

    return (
      <tr>
        <td>
          <a class="ct-admin__rule-name-link" href={editPath}>
            <strong>{name}</strong>
          </a>
          <AdminMeta>Setup in progress</AdminMeta>
        </td>
        <td>{templateTitle}</td>
        <td>{lmsLabel}</td>
        <td>Not active</td>
        <td>
          <strong>Setup incomplete</strong>
          <AdminMeta>Finish setup to create version 1</AdminMeta>
          <AdminStatusPill tone="draft">Draft</AdminStatusPill>
        </td>
        <td>{formatIsoTimestamp(draft.updatedAt)}</td>
        <td>
          <AdminActions>
            <AdminButtonLink href={editPath} variant="secondary" size="tiny">
              Edit
            </AdminButtonLink>
            <AdminForm
              method="post"
              action={tenantBadgeRuleBuilderDraftDeleteAdminPath(input.tenantId, draft.id)}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Delete unfinished draft "${name}"?`,
              }}
            >
              <AdminButton type="submit" size="tiny" variant="danger">
                Delete
              </AdminButton>
            </AdminForm>
          </AdminActions>
        </td>
      </tr>
    );
  });
};
