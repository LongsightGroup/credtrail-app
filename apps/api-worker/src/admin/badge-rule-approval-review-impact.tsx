import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeRuleImpactPreview } from "../lti/badge-rule-impact-preview";
import { formatIsoTimestamp } from "../utils/display-format";
import { buildBadgeRuleVersionImpactPreviewPath } from "./access-admin-helpers";
import { AdminActions, AdminButton, AdminForm, AdminMeta, AdminPanel } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

/** Renders the on-demand learner impact preview for a reviewed version. */
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
        <h2>Learner impact</h2>
        <p>
          Check how many learners would qualify if this version were activated now. This reads
          current LMS data and may take a moment.
        </p>
        <AdminForm method="post" action={refreshPath}>
          <AdminActions>
            <AdminButton type="submit" variant="secondary">
              Check learner impact
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
        <h2>Learner impact</h2>
        <p>{preview.reason}</p>
        <AdminMeta>Generated {formatIsoTimestamp(preview.generatedAt)}</AdminMeta>
        <AdminForm method="post" action={refreshPath}>
          <AdminActions>
            <AdminButton type="submit" variant="secondary">
              Refresh impact
            </AdminButton>
          </AdminActions>
        </AdminForm>
      </AdminPanel>
    );
  }

  return (
    <AdminPanel className="ct-admin__review-impact-panel">
      <h2>Learner impact</h2>
      <p>
        If activated now, <strong>{String(preview.eligibleNowCount)}</strong> learner
        {preview.eligibleNowCount === 1 ? "" : "s"} in{" "}
        <strong>{preview.courseTitle ?? preview.courseContextId ?? "this course"}</strong> would
        immediately earn this badge.
      </p>
      <AdminMeta>
        Evaluated {String(preview.evaluatedLearnerCount)} learner
        {preview.evaluatedLearnerCount === 1 ? "" : "s"} · Generated{" "}
        {formatIsoTimestamp(preview.generatedAt)}
      </AdminMeta>
      <AdminForm method="post" action={refreshPath}>
        <AdminActions>
          <AdminButton type="submit" variant="secondary">
            Refresh impact
          </AdminButton>
        </AdminActions>
      </AdminForm>
    </AdminPanel>
  );
};
