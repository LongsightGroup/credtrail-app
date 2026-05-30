/** Server-rendered badge template history dialog content (admin UI). */
import type { BadgeTemplateImageRevisionRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeTemplateHistoryTimelineEntry } from "../badges/badge-template-history";
import type { BadgeTemplateListPageQueryOptions } from "./badge-template-admin-helpers";
import { buildBadgeTemplateListPageQuery } from "./badge-template-admin-helpers";
import { formatIsoTimestamp } from "../utils/display-format";
import { AdminButton, AdminForm } from "./components";

const badgeTemplateImageRevisionSourceLabel = (
  sourceType: BadgeTemplateImageRevisionRecord["sourceType"],
): string => {
  switch (sourceType) {
    case "upload":
      return "Uploaded";
    case "ai_generated":
      return "Generated";
    case "restore":
      return "Restored";
    case "manual_update":
      return "Updated";
    default:
      return sourceType;
  }
};

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const BadgeTemplateHistoryTimeline = ({
  timeline,
}: {
  timeline: readonly BadgeTemplateHistoryTimelineEntry[];
}): HonoElement => {
  if (timeline.length === 0) {
    return <p class="ct-admin__empty">No edit history is recorded for this badge template yet.</p>;
  }

  return (
    <>
      {timeline.map((entry) => (
        <article class="ct-admin__history-audit-item" key={entry.id}>
          <strong>{entry.summary}</strong>
          <div class="ct-admin__history-audit-meta">
            {formatIsoTimestamp(entry.occurredAt)} · {entry.actorLabel}
          </div>
          {entry.detail.length > 0 ? (
            <p class="ct-admin__history-audit-detail">{entry.detail}</p>
          ) : null}
        </article>
      ))}
    </>
  );
};

export const BadgeTemplateImageRevisionList = ({
  revisions,
  restorePathPrefix,
  listPageQuery,
}: {
  revisions: readonly BadgeTemplateImageRevisionRecord[];
  restorePathPrefix: string;
  listPageQuery: BadgeTemplateListPageQueryOptions;
}): HonoElement => {
  const listQueryString = buildBadgeTemplateListPageQuery(listPageQuery).toString();
  const listQuerySuffix = listQueryString.length > 0 ? `?${listQueryString}` : "";
  if (revisions.length === 0) {
    return (
      <p class="ct-admin__empty">No image history is available for this badge template.</p>
    );
  }

  return (
    <>
      {revisions.map((revision) => {
        const previousImageUri = revision.previousImageUri ?? "";
        const restorePath = `${restorePathPrefix}/${encodeURIComponent(revision.id)}/restore${listQuerySuffix}`;

        return (
          <div class="ct-admin__image-revision-item" key={revision.id}>
            {previousImageUri.length > 0 ? (
              <a
                class="ct-admin__image-revision-thumbnail-link"
                href={previousImageUri}
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Open full size previous badge image"
              >
                <img
                  class="ct-admin__image-revision-thumbnail"
                  src={previousImageUri}
                  alt="Previous badge artwork"
                  loading="lazy"
                />
              </a>
            ) : (
              <span class="ct-admin__image-revision-thumbnail-link ct-admin__image-revision-thumbnail-link--empty">
                No image
              </span>
            )}
            <div class="ct-admin__image-revision-meta">
              <strong>
                {badgeTemplateImageRevisionSourceLabel(revision.sourceType)} ·{" "}
                {formatIsoTimestamp(revision.createdAt)}
              </strong>
              <span>
                {previousImageUri.length > 0
                  ? "Restore the previous image"
                  : "Restore to no image"}
              </span>
            </div>
            <div class="ct-admin__image-revision-actions">
              {previousImageUri.length > 0 ? (
                <a
                  class="ct-admin__text-action"
                  href={previousImageUri}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Open full size
                </a>
              ) : null}
              <AdminForm method="post" action={restorePath} className="ct-admin__inline-form">
                <AdminButton type="submit" variant="secondary" size="tiny">
                  Restore
                </AdminButton>
              </AdminForm>
            </div>
          </div>
        );
      })}
    </>
  );
};
