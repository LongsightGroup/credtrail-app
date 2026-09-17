import type { BadgeTemplateWorkflow } from "./badge-workflow-responsibility";
import { issuePreparedBadgePath } from "./badge-awarding-links";
/** Server-rendered badge template table row for the admin UI. */
import type { BadgeTemplateRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import {
  badgeTemplateAdminEditorHref,
  buildBadgeTemplateListPageQuery,
  type BadgeTemplateListPageQueryOptions,
} from "./badge-template-admin-helpers";
import {
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
} from "../badges/badge-template-public-links";
import {
  AdminMeta,
  AdminButton,
  AdminActionMenu,
  AdminActionMenuLink,
  AdminActions,
  AdminButtonLink,
  AdminForm,
  AdminStatusPill,
} from "./components";
import { AdminLinkedImageWithFallback } from "./image-fallback";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const BadgeTemplateAdminTableRow = ({
  tenantId,
  prepared = false,
  template,
  workflow,
  imageRevisionCount = 0,
  historyHref,
  rulesTemplatesPath,
  listPageQuery,
}: {
  tenantId: string;
  prepared?: boolean;
  template: BadgeTemplateRecord;
  workflow?: BadgeTemplateWorkflow | undefined;
  imageRevisionCount?: number;
  historyHref: string;
  rulesTemplatesPath: string;
  listPageQuery: BadgeTemplateListPageQueryOptions;
}): HonoElement => {
  const listQueryString = buildBadgeTemplateListPageQuery(listPageQuery).toString();
  const listQuerySuffix = listQueryString.length > 0 ? `?${listQueryString}` : "";
  const archiveAction = `${rulesTemplatesPath}/${encodeURIComponent(template.id)}/archive${listQuerySuffix}`;
  const unarchiveAction = `${rulesTemplatesPath}/${encodeURIComponent(template.id)}/unarchive${listQuerySuffix}`;
  return (
    <tr
      data-template-row-id={template.id}
      data-template-archived={template.isArchived ? "true" : "false"}
    >
      <td>
        {template.imageUri === null ? (
          <span class="ct-admin__template-placeholder">No image</span>
        ) : (
          <AdminLinkedImageWithFallback
            href={template.imageUri}
            linkClassName="ct-admin__template-image-link"
            imageClassName="ct-admin__template-image"
            placeholderClassName="ct-admin__template-placeholder"
            ariaLabel={`Open full size image for ${template.title}`}
            alt={`${template.title} artwork`}
            placeholderText="Image unavailable"
          />
        )}
      </td>
      <td>
        <strong>{template.title}</strong>
        {workflow === undefined ? null : (
          <>
            <AdminMeta>Badge owner: {workflow.badgeOwner}</AdminMeta>
            <AdminMeta>Created by: {workflow.badgeCreator}</AdminMeta>
          </>
        )}
      </td>
      <td>
        {template.isArchived ? (
          <AdminStatusPill tone="revoked">Archived</AdminStatusPill>
        ) : (
          <AdminStatusPill tone={prepared ? "active" : "pending"}>
            {prepared
              ? "Ready to award"
              : template.imageUri === null
                ? "Needs artwork"
                : "Artwork needs attention"}
          </AdminStatusPill>
        )}
      </td>
      <td>{formatIsoTimestamp(template.updatedAt)}</td>
      <td>
        <AdminActions>
          {template.isArchived ? (
            <AdminForm
              method="post"
              action={unarchiveAction}
              className="ct-admin__restore-template-form"
            >
              <AdminButton type="submit" variant="primary" size="tiny">
                Restore template
              </AdminButton>
            </AdminForm>
          ) : null}
          <AdminButtonLink
            href={badgeTemplateAdminEditorHref(tenantId, template.id, listPageQuery)}
            variant="secondary"
            size="tiny"
          >
            Edit template
          </AdminButtonLink>
          {prepared && !template.isArchived ? (
            <AdminButtonLink
              href={issuePreparedBadgePath(tenantId, template.id)}
              variant="secondary"
              size="tiny"
            >
              Issue this badge
            </AdminButtonLink>
          ) : null}
          <AdminActionMenu
            menuId={`badge-template-action-menu-${template.id}`}
            ariaLabel={`More actions for ${template.title}`}
          >
            <AdminActionMenuLink
              href={badgeTemplateShowcaseHref(tenantId, template.id)}
              target="_blank"
              rel="noopener noreferrer"
            >
              View public page ↗
            </AdminActionMenuLink>
            <AdminActionMenuLink
              href={badgeTemplateCriteriaRegistryHref(tenantId, template.id)}
              target="_blank"
              rel="noopener noreferrer"
            >
              View criteria page ↗
            </AdminActionMenuLink>
            <AdminActionMenuLink
              href={historyHref}
              dataAttributes={{
                "data-template-history-template-id": template.id,
                "data-template-history-template-title": template.title,
                "data-template-history-image-revision-count": String(imageRevisionCount),
              }}
            >
              View history
            </AdminActionMenuLink>
          </AdminActionMenu>
        </AdminActions>
        {template.isArchived ? null : (
          <details class="ct-admin__archive-disclosure">
            <summary>Archive template</summary>
            <AdminForm method="post" action={archiveAction} className="ct-stack">
              <p>
                Archiving removes this template from manual awarding and new rule setup. Published
                rules can still issue badges from their approved version.
              </p>
              <p>
                Existing credentials and their public pages stay unchanged. You can restore this
                template from the list at any time.
              </p>
              <AdminButton type="submit" variant="danger" size="tiny">
                Archive template
              </AdminButton>
            </AdminForm>
          </details>
        )}
      </td>
    </tr>
  );
};
