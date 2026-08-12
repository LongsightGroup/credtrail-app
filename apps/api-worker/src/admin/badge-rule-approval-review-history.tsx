import type {
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import { badgeRuleApprovalStepTargetLabel } from "./badge-rule-approvals-shell";
import { AdminMeta, AdminPanel, AdminStatusPill } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

/** Renders approval progress and the optional full audit disclosure. */
export const BadgeRuleApprovalReviewHistory = (input: {
  readonly steps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  readonly events: readonly BadgeIssuanceRuleApprovalEventRecord[];
}): HonoElement => {
  return (
    <AdminPanel className="ct-admin__review-approval-progress">
      <h2>Approval progress</h2>
      <ol class="ct-admin__review-approval-chain" role="list">
        {input.steps.map((step) => (
          <li>
            <span class="ct-admin__review-approval-step-number" aria-hidden="true">
              {String(step.stepNumber)}
            </span>
            <div>
              <div class="ct-admin__review-approval-step-heading">
                <strong>{step.label ?? `Step ${String(step.stepNumber)}`}</strong>
                <AdminStatusPill tone={step.status}>
                  {step.status.replaceAll("_", " ")}
                </AdminStatusPill>
              </div>
              <AdminMeta>
                {badgeRuleApprovalStepTargetLabel(step)}
                {step.decidedAt === null ? "" : ` · Decided ${formatIsoTimestamp(step.decidedAt)}`}
              </AdminMeta>
              {step.decisionComment === null ? null : <p>{step.decisionComment}</p>}
            </div>
          </li>
        ))}
      </ol>
      {input.events.length === 0 ? null : (
        <details class="ct-admin__review-audit-history">
          <summary>
            Show full audit history ({String(input.events.length)} event
            {input.events.length === 1 ? "" : "s"})
          </summary>
          <ol>
            {input.events.map((event) => (
              <li>
                <strong>{event.action.replaceAll("_", " ")}</strong>{" "}
                <span>· {formatIsoTimestamp(event.occurredAt)}</span>
                <AdminMeta>{event.actorUserId ?? "System"}</AdminMeta>
                {event.comment === null ? null : <p>{event.comment}</p>}
              </li>
            ))}
          </ol>
        </details>
      )}
    </AdminPanel>
  );
};
