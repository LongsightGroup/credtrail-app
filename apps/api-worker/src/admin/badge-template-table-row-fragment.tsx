/** Server-rendered badge template table row fragment for the admin UI. */
import type { BadgeTemplateRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import { AdminMeta, AdminStatusPill } from "./components";

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

export const BadgeTemplateAdminTableRow = ({
  tenantId,
  template,
  imageRevisionCount = 0,
  historyHref,
}: {
  tenantId: string;
  template: BadgeTemplateRecord;
  imageRevisionCount?: number;
  historyHref: string;
}): HonoElement => {
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
        {imageRevisionCount > 0 ? (
          <AdminMeta as="span">
            {imageRevisionCount === 1
              ? "1 image version"
              : `${String(imageRevisionCount)} image versions`}
          </AdminMeta>
        ) : null}
      </td>
      <td>
        {template.isArchived ? (
          <AdminStatusPill tone="revoked">Archived</AdminStatusPill>
        ) : (
          <AdminStatusPill tone="active">Active</AdminStatusPill>
        )}
      </td>
      <td>{template.id}</td>
      <td>{formatIsoTimestamp(template.updatedAt)}</td>
      <td>
        <div class="ct-admin__template-actions">
          <button
            type="button"
            class="ct-admin__text-action ct-admin__template-primary-action"
            data-template-edit-template-id={template.id}
          >
            Edit
          </button>
          <span class="ct-admin__template-secondary-actions" aria-label="Public template links">
            <a
              href={badgeTemplateShowcaseHref(tenantId, template.id)}
              target="_blank"
              rel="noopener noreferrer"
            >
              Public
            </a>
            <a
              href={badgeTemplateCriteriaRegistryHref(tenantId, template.id)}
              target="_blank"
              rel="noopener noreferrer"
            >
              Criteria
            </a>
            <a
              href={historyHref}
              data-template-history-template-id={template.id}
              data-template-history-template-title={template.title}
              data-template-history-image-revision-count={String(imageRevisionCount)}
            >
              History
            </a>
          </span>
        </div>
      </td>
    </tr>
  );
};

export const renderBadgeTemplateAdminTableRowToString = (input: {
  tenantId: string;
  template: BadgeTemplateRecord;
  imageRevisionCount?: number;
  historyHref: string;
}): string => {
  const renderable = (<BadgeTemplateAdminTableRow {...input} />) as { toString(): string };

  return renderable.toString();
};
