/** Server-rendered badge template table row fragment for the admin UI. */
import type { BadgeTemplateRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import {
  buildBadgeTemplateListPageQuery,
  type BadgeTemplateListPageQueryOptions,
} from "./badge-template-admin-helpers";
import {
  AdminActionMenu,
  AdminActionMenuLink,
  AdminButtonLink,
  AdminForm,
  AdminStatusPill,
} from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const badgeTemplateShowcaseHref = (tenantId: string, badgeTemplateId: string): string => {
  return `/showcase/${encodeURIComponent(tenantId)}?badgeTemplateId=${encodeURIComponent(
    badgeTemplateId,
  )}`;
};

export const badgeTemplateCriteriaRegistryHref = (
  tenantId: string,
  badgeTemplateId: string,
): string => {
  return `/showcase/${encodeURIComponent(tenantId)}/criteria?badgeTemplateId=${encodeURIComponent(
    badgeTemplateId,
  )}`;
};

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
          <a
            class="ct-admin__template-image-link"
            href={template.imageUri}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={`Open full size image for ${template.title}`}
          >
            <img
              class="ct-admin__template-image"
              src={template.imageUri}
              alt={`${template.title} artwork`}
              loading="lazy"
            />
          </a>
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
        <div class="ct-admin__template-actions">
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
              <AdminForm method="post" action={unarchiveAction} className="ct-admin__action-menu-form">
                <button type="submit" class="ct-admin__action-menu-item">
                  Restore
                </button>
              </AdminForm>
            ) : (
              <AdminForm method="post" action={archiveAction} className="ct-admin__action-menu-form">
                <button
                  type="submit"
                  class="ct-admin__action-menu-item ct-admin__action-menu-item--danger"
                >
                  Archive
                </button>
              </AdminForm>
            )}
          </AdminActionMenu>
        </div>
      </td>
    </tr>
  );
};

