/** Server-rendered badge template table row for the admin UI. */
import type { BadgeTemplateRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import {
  buildBadgeTemplateListPageQuery,
  type BadgeTemplateListPageQueryOptions,
} from "./badge-template-admin-helpers";
import {
  badgeTemplateCriteriaRegistryHref,
  badgeTemplateShowcaseHref,
} from "../badges/badge-template-public-links";
import {
  AdminActionMenu,
  AdminActionMenuLink,
  AdminActions,
  AdminButtonLink,
  AdminForm,
  AdminStatusPill,
} from "./components";
import { AdminLinkedImageWithFallback } from "./image-fallback";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const badgeTemplateAdminEditorHref = (tenantId: string, badgeTemplateId: string): string => {
  return `/tenants/${encodeURIComponent(tenantId)}/admin/rules/templates/${encodeURIComponent(
    badgeTemplateId,
  )}`;
};

export const BadgeTemplateAdminTableRow = ({
  tenantId,
  template,
  imageRevisionCount = 0,
  historyHref,
  rulesTemplatesPath,
  listPageQuery,
}: {
  tenantId: string;
  template: BadgeTemplateRecord;
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
      </td>
      <td>
        {template.isArchived ? (
          <AdminStatusPill tone="revoked">Archived</AdminStatusPill>
        ) : (
          <AdminStatusPill tone="active">Active</AdminStatusPill>
        )}
      </td>
      <td>{formatIsoTimestamp(template.updatedAt)}</td>
      <td>
        <AdminActions>
          <AdminButtonLink
            href={badgeTemplateAdminEditorHref(tenantId, template.id)}
            variant="secondary"
            size="tiny"
          >
            Edit template
          </AdminButtonLink>
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
            {template.isArchived ? (
              <AdminForm
                method="post"
                action={unarchiveAction}
                className="ct-admin__action-menu-form"
              >
                <button type="submit" class="ct-admin__action-menu-item">
                  Restore
                </button>
              </AdminForm>
            ) : (
              <AdminForm
                method="post"
                action={archiveAction}
                className="ct-admin__action-menu-form"
              >
                <button
                  type="submit"
                  class="ct-admin__action-menu-item ct-admin__action-menu-item--danger"
                >
                  Archive
                </button>
              </AdminForm>
            )}
          </AdminActionMenu>
        </AdminActions>
      </td>
    </tr>
  );
};
