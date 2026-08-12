import { BADGE_ISSUANCE_RULE_DECISIONS_REQUIRING_COMMENT } from "@credtrail/validation";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtCheckboxControl, CtTextarea } from "../ui/forms";
import {
  buildBadgeRuleVersionReviewDecisionPath,
  buildBadgeRuleVersionReviewReopenPath,
} from "./access-admin-helpers";
import type { BadgeRuleReviewAction } from "./badge-rule-approval-review-model";
import { AdminActions, AdminButton, AdminField, AdminForm, AdminPanel } from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const renderDecisionChoice = (input: {
  readonly value: "approved" | "changes_requested" | "rejected";
  readonly label: string;
  readonly description: string;
  readonly tone?: "danger" | undefined;
}): HonoElement => {
  const controlId = `rule-review-decision-${input.value}`;
  const descriptionId = `rule-review-decision-${input.value}-description`;

  return (
    <label
      htmlFor={controlId}
      class="ct-admin__review-decision-choice"
      data-tone={input.tone}
      data-rule-review-decision-choice=""
    >
      <CtCheckboxControl
        id={controlId}
        name="decision"
        type="radio"
        value={input.value}
        required
        describedBy={descriptionId}
        dataAttributes={{ "data-rule-review-decision": "" }}
      />
      <span>
        <strong>{input.label}</strong>
        <small id={descriptionId}>{input.description}</small>
      </span>
    </label>
  );
};

const renderDecisionForm = (input: {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
}): HonoElement => {
  return (
    <AdminPanel className="ct-admin__review-decision-panel">
      <h2 id="rule-review-decision-heading">Record your decision</h2>
      <p>Choose one outcome for this immutable version.</p>
      <AdminForm
        method="post"
        action={buildBadgeRuleVersionReviewDecisionPath(
          input.tenantId,
          input.ruleId,
          input.versionId,
        )}
        dataAttributes={{
          "data-rule-review-decision-form": "",
          "data-rule-review-comment-required-decisions":
            BADGE_ISSUANCE_RULE_DECISIONS_REQUIRING_COMMENT.join(" "),
        }}
      >
        <fieldset class="ct-admin__review-decision-choices">
          <legend>Decision</legend>
          {renderDecisionChoice({
            value: "approved",
            label: "Approve version",
            description: "Accept this version and allow it to continue toward activation.",
          })}
          {renderDecisionChoice({
            value: "changes_requested",
            label: "Return for changes",
            description: "Send it back to draft so the author can revise and resubmit.",
          })}
          {renderDecisionChoice({
            value: "rejected",
            label: "Reject version",
            description:
              "End this submission. It remains in the audit record and cannot be activated.",
            tone: "danger",
          })}
        </fieldset>
        <AdminField label="Reviewer comment">
          <CtTextarea
            id="rule-review-comment"
            name="comment"
            rows={4}
            variant="prose"
            maxlength={2000}
            describedBy="rule-review-comment-hint"
            placeholder="Explain your decision for the author or next reviewer."
            dataAttributes={{ "data-rule-review-comment": "" }}
          />
          <span
            id="rule-review-comment-hint"
            class="ct-field__hint"
            data-rule-review-comment-hint=""
          >
            Optional when approving. Required when returning for changes or rejecting.
          </span>
        </AdminField>
        <AdminActions>
          <AdminButton type="submit" variant="primary">
            Record decision
          </AdminButton>
        </AdminActions>
      </AdminForm>
    </AdminPanel>
  );
};

/** Renders the one decision action available for the reviewed version. */
export const BadgeRuleApprovalReviewDecision = (input: {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly action: BadgeRuleReviewAction;
}): HonoElement => {
  if (input.action.kind === "decide") {
    return renderDecisionForm(input);
  }

  if (input.action.kind === "reopen") {
    return (
      <AdminPanel className="ct-admin__review-decision-panel">
        <h2>Correct this approval</h2>
        <p>
          If this version was approved by mistake, reopen it before activation. The version returns
          to draft and must be submitted again.
        </p>
        <AdminForm
          method="post"
          action={buildBadgeRuleVersionReviewReopenPath(
            input.tenantId,
            input.ruleId,
            input.versionId,
          )}
        >
          <AdminField label="Reason for reopening">
            <CtTextarea
              name="comment"
              rows={4}
              variant="prose"
              placeholder="Explain what needs to be corrected."
              required
            />
          </AdminField>
          <AdminActions>
            <AdminButton type="submit" variant="secondary">
              Reopen as draft
            </AdminButton>
          </AdminActions>
        </AdminForm>
      </AdminPanel>
    );
  }

  return (
    <AdminPanel className="ct-admin__review-decision-panel">
      <h2>Decision</h2>
      <p>No approval action is available for this version.</p>
    </AdminPanel>
  );
};
