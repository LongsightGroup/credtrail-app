import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtInput } from "../ui/forms";
import {
  buildBadgeRuleCopyPath,
  buildBadgeRuleDetailPath,
  buildBadgeRulePlacementAvailabilityPath,
  buildBadgeRuleVersionDetailPath,
  buildBadgeRuleVersionReviewPath,
  tenantBadgeRuleActivateAdminPath,
  tenantBadgeRuleResumeAdminPath,
  tenantBadgeRuleSubmitApprovalAdminPath,
  tenantBadgeRuleUpdateLifecycleAdminPath,
  tenantBadgeRuleWithdrawSubmissionAdminPath,
} from "./access-admin-helpers";
import { AdminActions, AdminButton, AdminButtonLink, AdminForm, AdminPanel } from "./components";
import { buildBadgeRuleNextStepModel, type BadgeRuleNextStepAction } from "./badge-rule-next-step";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface BadgeRuleNextStepPanelInput {
  readonly tenantId: string;
  readonly userId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly selectedVersion: BadgeIssuanceRuleVersionRecord;
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
  readonly definition: BadgeIssuanceRuleDefinition;
  readonly activePlacementCount: number;
  readonly canReviewPendingVersion: boolean;
}

const editRulePath = (tenantId: string, ruleId: string): string => {
  return `${buildBadgeRuleDetailPath(tenantId, ruleId)}/edit`;
};

const NextStepAction = (input: {
  readonly panel: BadgeRuleNextStepPanelInput;
  readonly action: BadgeRuleNextStepAction;
}): HonoElement => {
  const { panel, action } = input;
  const ruleName = panel.latestVersion.snapshot.name;

  switch (action._tag) {
    case "view_latest":
      return (
        <AdminButtonLink
          href={buildBadgeRuleVersionDetailPath(
            panel.tenantId,
            panel.rule.id,
            panel.latestVersion.id,
          )}
        >
          Open version {String(panel.latestVersion.versionNumber)}
        </AdminButtonLink>
      );
    case "submit_for_approval":
      return (
        <AdminActions>
          <AdminForm
            method="post"
            action={tenantBadgeRuleSubmitApprovalAdminPath(
              panel.tenantId,
              panel.rule.id,
              panel.latestVersion.id,
            )}
            className="ct-admin__inline-form"
            dataAttributes={{
              "data-confirm-message": `Submit draft version for "${ruleName}" for approval? You will not be able to approve it yourself.`,
            }}
          >
            <AdminButton type="submit">Submit for approval</AdminButton>
          </AdminForm>
          <AdminButtonLink href={editRulePath(panel.tenantId, panel.rule.id)} variant="quiet">
            Edit draft
          </AdminButtonLink>
        </AdminActions>
      );
    case "edit_rule":
      return (
        <AdminButtonLink href={editRulePath(panel.tenantId, panel.rule.id)}>
          Revise rule
        </AdminButtonLink>
      );
    case "review_approval":
      return (
        <AdminButtonLink
          href={buildBadgeRuleVersionReviewPath(
            panel.tenantId,
            panel.rule.id,
            panel.latestVersion.id,
          )}
        >
          Review submission
        </AdminButtonLink>
      );
    case "await_approval":
      return (
        <AdminActions>
          <AdminButtonLink
            href={buildBadgeRuleVersionReviewPath(
              panel.tenantId,
              panel.rule.id,
              panel.latestVersion.id,
            )}
            variant="secondary"
          >
            View submission
          </AdminButtonLink>
          {action.canWithdraw ? (
            <AdminForm
              method="post"
              action={tenantBadgeRuleWithdrawSubmissionAdminPath(
                panel.tenantId,
                panel.rule.id,
                panel.latestVersion.id,
              )}
              className="ct-admin__inline-form"
              dataAttributes={{
                "data-confirm-message": `Withdraw "${ruleName}" from approval and return it to draft?`,
              }}
            >
              <AdminButton type="submit" variant="quiet">
                Withdraw submission
              </AdminButton>
            </AdminForm>
          ) : null}
        </AdminActions>
      );
    case "activate":
      return (
        <AdminActions>
          <AdminForm
            method="post"
            action={tenantBadgeRuleActivateAdminPath(
              panel.tenantId,
              panel.rule.id,
              panel.latestVersion.id,
            )}
            className="ct-admin__inline-form"
            dataAttributes={{
              "data-confirm-message": `Activate "${ruleName}" for new awards?`,
            }}
          >
            <AdminButton type="submit">Activate rule</AdminButton>
          </AdminForm>
          <AdminButtonLink
            href={buildBadgeRuleVersionReviewPath(
              panel.tenantId,
              panel.rule.id,
              panel.latestVersion.id,
            )}
            variant="quiet"
          >
            Review approval
          </AdminButtonLink>
        </AdminActions>
      );
    case "configure_availability":
      return (
        <AdminButtonLink
          href={buildBadgeRulePlacementAvailabilityPath(panel.tenantId, panel.rule.id)}
        >
          Set course availability
        </AdminButtonLink>
      );
    case "review_evaluation":
      return (
        <AdminButtonLink href="#automatic-evaluation" variant="secondary">
          Review evaluation health
        </AdminButtonLink>
      );
    case "schedule_end_of_term":
      return (
        <AdminForm
          method="post"
          action={tenantBadgeRuleUpdateLifecycleAdminPath(
            panel.tenantId,
            panel.rule.id,
            panel.latestVersion.id,
          )}
          className="ct-admin__rule-next-step-schedule"
        >
          <label htmlFor={`badge-rule-end-date-${panel.rule.id}`}>Term end date</label>
          <CtInput
            id={`badge-rule-end-date-${panel.rule.id}`}
            name="expiresAt"
            type="datetime-local"
            required
          />
          <AdminButton type="submit">Schedule end-of-term batch</AdminButton>
        </AdminForm>
      );
    case "review_availability":
      return (
        <AdminButtonLink
          href={buildBadgeRulePlacementAvailabilityPath(panel.tenantId, panel.rule.id)}
          variant="secondary"
        >
          Review course availability
        </AdminButtonLink>
      );
    case "resume":
      return (
        <AdminForm
          method="post"
          action={tenantBadgeRuleResumeAdminPath(
            panel.tenantId,
            panel.rule.id,
            panel.latestVersion.id,
          )}
          className="ct-admin__inline-form"
          dataAttributes={{
            "data-confirm-message": `Resume issuance for "${ruleName}"?`,
          }}
        >
          <AdminButton type="submit">Resume issuance</AdminButton>
        </AdminForm>
      );
    case "copy_rule":
      return (
        <AdminButtonLink href={buildBadgeRuleCopyPath(panel.tenantId, panel.rule.id)}>
          Copy into a new rule
        </AdminButtonLink>
      );
  }
};

/** Renders the current owner, expected outcome, and one primary next rule action. */
export const BadgeRuleNextStepPanel = (input: BadgeRuleNextStepPanelInput): HonoElement => {
  const model = buildBadgeRuleNextStepModel(input);

  return (
    <AdminPanel
      as="section"
      className="ct-admin__rule-next-step"
      dataAttributes={{ "data-rule-next-step": model.action._tag }}
    >
      <div class="ct-admin__rule-next-step-layout">
        <div class="ct-admin__rule-next-step-copy">
          <h2>What happens next</h2>
          <p class="ct-admin__rule-next-step-title">{model.title}</p>
          <p>{model.description}</p>
          <dl class="ct-admin__rule-next-step-ownership">
            <div>
              <dt>Next owner</dt>
              <dd>{model.owner}</dd>
            </div>
            <div>
              <dt>After this</dt>
              <dd>{model.outcome}</dd>
            </div>
          </dl>
        </div>
        <div class="ct-admin__rule-next-step-action">
          <NextStepAction panel={input} action={model.action} />
        </div>
      </div>
    </AdminPanel>
  );
};
