import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import type { Child } from "hono/jsx";
import {
  buildBadgeRuleVersionReviewPath,
  tenantBadgeRuleDeleteAdminPath,
  tenantBadgeRuleSubmitApprovalAdminPath,
  tenantBadgeRuleWithdrawSubmissionAdminPath,
} from "../access-admin-helpers";
import { AdminForm } from "../components";
import { buildBadgeRuleLifecycleMenuActions } from "./badge-rule-lifecycle-actions";

/** Builds the complete ordered action menu for one badge-rule workflow. */
export const buildBadgeRuleWorkflowMenuActions = (input: {
  readonly tenantId: string;
  readonly userId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
  readonly canDeleteRule: boolean;
}): Child[] => {
  const { tenantId, userId, rule, latestVersion } = input;
  const menuActions: Child[] = [];

  if (latestVersion.status === "draft" || latestVersion.status === "rejected") {
    menuActions.push(
      <AdminForm
        method="post"
        action={tenantBadgeRuleSubmitApprovalAdminPath(tenantId, rule.id, latestVersion.id)}
        className="ct-admin__inline-form"
        dataAttributes={{
          "data-confirm-message": `Submit draft version for "${latestVersion.snapshot.name}" for approval? You will not be able to approve it yourself.`,
        }}
      >
        <button type="submit" class="ct-admin__action-menu-item">
          Submit for approval
        </button>
      </AdminForm>,
    );
  }

  if (latestVersion.status === "pending_approval" && latestVersion.submittedByUserId === userId) {
    menuActions.push(
      <AdminForm
        method="post"
        action={tenantBadgeRuleWithdrawSubmissionAdminPath(tenantId, rule.id, latestVersion.id)}
        className="ct-admin__inline-form"
        dataAttributes={{
          "data-confirm-message": `Withdraw "${latestVersion.snapshot.name}" from approval and return it to draft?`,
        }}
      >
        <button type="submit" class="ct-admin__action-menu-item">
          Withdraw submission
        </button>
      </AdminForm>,
    );
  }

  if (latestVersion.status === "approved" && latestVersion.approvedByUserId === userId) {
    menuActions.push(
      <a
        class="ct-admin__action-menu-item"
        href={buildBadgeRuleVersionReviewPath(tenantId, rule.id, latestVersion.id)}
      >
        Review approval
      </a>,
    );
  }

  menuActions.push(
    ...buildBadgeRuleLifecycleMenuActions({
      tenantId,
      rule,
      latestVersion,
    }),
  );

  if (input.canDeleteRule) {
    menuActions.push(
      <AdminForm
        method="post"
        action={tenantBadgeRuleDeleteAdminPath(tenantId, rule.id)}
        className="ct-admin__action-menu-form"
        dataAttributes={{
          "data-confirm-message": `Delete draft rule "${latestVersion.snapshot.name}"? This removes its draft and rejected versions.`,
        }}
      >
        <button type="submit" class="ct-admin__action-menu-item ct-admin__action-menu-item--danger">
          Delete
        </button>
      </AdminForm>,
    );
  }

  return menuActions;
};
