import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeRuleReviewComparison } from "./badge-rule-approval-review-model";
import { AdminMeta, AdminPanel } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

/** Renders the immutable setting and requirement changes under review. */
export const BadgeRuleApprovalReviewDiff = (input: {
  readonly comparison: BadgeRuleReviewComparison;
}): HonoElement => {
  if (input.comparison.kind === "unavailable") {
    return (
      <AdminPanel className="ct-admin__review-diff-panel">
        <h2>What changed</h2>
        <p>No earlier version is available for comparison.</p>
      </AdminPanel>
    );
  }

  const { comparison } = input;

  return (
    <AdminPanel className="ct-admin__review-diff-panel">
      <div class="ct-admin__review-section-heading">
        <div>
          <h2>What changed</h2>
          <AdminMeta>Compared with version {String(comparison.baseVersionNumber)}</AdminMeta>
        </div>
        <span class="ct-admin__review-change-count">
          {String(comparison.changeCount)} change{comparison.changeCount === 1 ? "" : "s"}
        </span>
      </div>

      <section class="ct-admin__review-diff-section">
        <h3>Rule settings</h3>
        {comparison.settingRows.length === 0 ? (
          <p>No rule setting changes.</p>
        ) : (
          <dl class="ct-admin__review-diff-rows">
            {comparison.settingRows.map((row) => (
              <div>
                <dt>{row.label}</dt>
                <dd>
                  <span>
                    <small>Before</small>
                    <span>{row.before}</span>
                  </span>
                  <span class="ct-admin__review-diff-arrow" aria-hidden="true">
                    →
                  </span>
                  <span>
                    <small>Now</small>
                    <span>{row.after}</span>
                  </span>
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      <section class="ct-admin__review-diff-section">
        <h3>Earning requirements</h3>
        {comparison.requirementChanges.length === 0 ? (
          <p>No earning requirement changes.</p>
        ) : (
          <ul class="ct-admin__review-requirement-diff" role="list">
            {comparison.requirementChanges.map((description) => (
              <li data-tone={description.reviewImpact === "loosening" ? "warning" : undefined}>
                {description.reviewImpact === "loosening" ? (
                  <strong>Loosens requirements</strong>
                ) : null}
                <span>{description.text}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </AdminPanel>
  );
};
