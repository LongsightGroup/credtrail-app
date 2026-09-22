import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeRuleImpactPreview } from "../lti/badge-rule-impact-preview";
import { formatIsoTimestamp } from "../utils/display-format";
import { buildBadgeRuleVersionImpactPreviewPath } from "./access-admin-helpers";
import { AdminActions, AdminButton, AdminForm, AdminMeta, AdminPanel } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

/** Renders the optional eligibility preview for a reviewed version. */
export const BadgeRuleApprovalReviewImpact = (input: {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly preview: BadgeRuleImpactPreview;
}): HonoElement => {
  const refreshPath = buildBadgeRuleVersionImpactPreviewPath(
    input.tenantId,
    input.ruleId,
    input.versionId,
  );

  if (input.preview.status === "not_requested") {
    return (
      <AdminPanel className="ct-admin__review-impact-panel">
        <h2>Eligible learners</h2>
        <p>
          Optional: Check how many learners in the linked course would qualify under this version.
          This reads current LMS data and may take a moment. No badges are issued.
        </p>
        <AdminForm method="post" action={refreshPath}>
          <AdminActions>
            <AdminButton type="submit" variant="secondary">
              Preview eligible learners
            </AdminButton>
          </AdminActions>
        </AdminForm>
      </AdminPanel>
    );
  }

  const { preview } = input;

  if (preview.status === "unavailable") {
    return (
      <AdminPanel className="ct-admin__review-impact-panel">
        <h2>Eligible learners</h2>
        <p>{preview.reason}</p>
        <AdminMeta>Generated {formatIsoTimestamp(preview.generatedAt)}</AdminMeta>
        <AdminForm method="post" action={refreshPath}>
          <AdminActions>
            <AdminButton type="submit" variant="secondary">
              Refresh preview
            </AdminButton>
          </AdminActions>
        </AdminForm>
      </AdminPanel>
    );
  }

  return (
    <AdminPanel className="ct-admin__review-impact-panel">
      <h2>Eligible learners</h2>
      <p>
        Based on current LMS data, <strong>{String(preview.eligibleNowCount)}</strong> learner
        {preview.eligibleNowCount === 1 ? "" : "s"} in{" "}
        <strong>{preview.courseTitle ?? preview.courseContextId ?? "this course"}</strong> would
        qualify for this badge under this version.
      </p>
      <p>This preview does not issue badges.</p>
      <AdminMeta>
        Evaluated {String(preview.evaluatedLearnerCount)} learner
        {preview.evaluatedLearnerCount === 1 ? "" : "s"} · Generated{" "}
        {formatIsoTimestamp(preview.generatedAt)}
      </AdminMeta>
      <AdminForm method="post" action={refreshPath}>
        <AdminActions>
          <AdminButton type="submit" variant="secondary">
            Refresh preview
          </AdminButton>
        </AdminActions>
      </AdminForm>
    </AdminPanel>
  );
};
