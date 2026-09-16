import type { BadgeTemplateRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeTemplateArtworkReadiness } from "../badges/badge-achievement-snapshot";
import { AdminActions, AdminButtonLink } from "./components";
import { automaticBadgeAwardingPath, issuePreparedBadgePath } from "./badge-awarding-links";

export const BadgePreparationActions = (input: {
  readonly template: BadgeTemplateRecord;
  readonly readiness: BadgeTemplateArtworkReadiness;
}): HtmlEscapedString | Promise<HtmlEscapedString> => {
  if (input.template.isArchived)
    return <p>Restore this template from the badge list before awarding it.</p>;
  if (input.readiness === "storage_unavailable")
    return <p>Artwork could not be checked. Reload this page to try again.</p>;
  if (input.readiness !== "ready")
    return (
      <>
        <p>
          {input.readiness === "missing_artwork"
            ? "Add artwork before awarding this badge."
            : "Replace the artwork before awarding this badge."}
        </p>
        <AdminActions>
          <AdminButtonLink href="#template-editor-artwork" variant="primary">
            {input.readiness === "missing_artwork" ? "Add artwork" : "Replace artwork"}
          </AdminButtonLink>
        </AdminActions>
      </>
    );
  return (
    <section aria-label="Award this badge" class="ct-stack">
      <AdminActions>
        <AdminButtonLink
          href={issuePreparedBadgePath(input.template.tenantId, input.template.id)}
          variant="primary"
        >
          Issue this badge
        </AdminButtonLink>
        <AdminButtonLink
          href={automaticBadgeAwardingPath(input.template.tenantId, input.template.id)}
          variant="secondary"
        >
          Set up automatic awarding
        </AdminButtonLink>
      </AdminActions>
      <p>
        Issue to a learner now, or create a rule that defines how learners qualify. Automatic
        awarding starts only after the rule is approved and activated.
      </p>
    </section>
  );
};
