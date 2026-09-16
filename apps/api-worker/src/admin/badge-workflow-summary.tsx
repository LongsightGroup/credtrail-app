import type { HtmlEscapedString } from "hono/utils/html";
import { AdminPanel } from "./components";
import type { BadgeWorkflowResponsibility } from "./badge-workflow-responsibility";

/** Shows the people and awarding method before a rule's primary workflow action. */
export const BadgeWorkflowSummary = (input: {
  readonly responsibility: BadgeWorkflowResponsibility | undefined;
}): HtmlEscapedString | Promise<HtmlEscapedString> | null => {
  const summary = input.responsibility;
  if (summary === undefined) return null;
  return (
    <AdminPanel as="section" className="ct-admin__workflow-summary">
      <h2>Who does what</h2>
      <dl class="ct-admin__workflow-facts">
        <div>
          <dt>Badge owner</dt>
          <dd>{summary.badgeOwner}</dd>
        </div>
        <div>
          <dt>Rule author</dt>
          <dd>{summary.ruleAuthor}</dd>
        </div>
        <div>
          <dt>Rule approval</dt>
          <dd>
            {summary.approval.label}
            <p class="ct-admin__hint">{summary.approval.detail}</p>
          </dd>
        </div>
        <div>
          <dt>Who awards the badge</dt>
          <dd>
            {summary.awarding}
            <p class="ct-admin__hint">{summary.awardingDetail}</p>
          </dd>
        </div>
      </dl>
    </AdminPanel>
  );
};
