/** Server-rendered HTML fragment for the badge template history dialog (admin UI only). */
import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeTemplateHistoryTimelineEntry } from "../badges/badge-template-history";
import { formatIsoTimestamp } from "../utils/display-format";

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

export const renderBadgeTemplateHistoryTimelineToString = (
  timeline: readonly BadgeTemplateHistoryTimelineEntry[],
): string => {
  const renderable = (<BadgeTemplateHistoryTimeline timeline={timeline} />) as { toString(): string };

  return renderable.toString();
};
