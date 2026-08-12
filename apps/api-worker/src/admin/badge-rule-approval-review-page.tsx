import type {
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleRecord,
  TenantOrgUnitRecord,
} from "@credtrail/db";
import type { BadgeIssuanceRuleDefinition } from "@credtrail/validation";
import { badgeRuleVersionDisplayFields } from "../badges/badge-rule-presentation";
import type { BadgeRuleImpactPreview } from "../lti/badge-rule-impact-preview";
import type { AppPage } from "../ui/render-page";
import { buildBadgeRuleApprovalsPath } from "./access-admin-helpers";
import { BadgeRuleApprovalReviewDecision } from "./badge-rule-approval-review-decision";
import { BadgeRuleApprovalReviewDiff } from "./badge-rule-approval-review-diff";
import { BadgeRuleApprovalReviewHistory } from "./badge-rule-approval-review-history";
import { BadgeRuleApprovalReviewImpact } from "./badge-rule-approval-review-impact";
import {
  buildBadgeRuleReviewComparison,
  BadgeRuleReviewAction,
} from "./badge-rule-approval-review-model";
import {
  renderBadgeRuleApprovalsShellPage,
  type BadgeRuleApprovalsShellInput,
} from "./badge-rule-approvals-shell";
import {
  BadgeRuleVersionNavigator,
  type BadgeRuleVersionNavigationModel,
} from "./badge-rule-version-navigator";
import { BadgeRuleVersionOverview } from "./badge-rule-version-overview";
import { AdminPageHeader, AdminStatus } from "./components";

/** Renders the focused reviewer workspace for one immutable badge-rule version. */
export const badgeRuleApprovalReviewPage = (
  shell: BadgeRuleApprovalsShellInput,
  input: {
    readonly rule: BadgeIssuanceRuleRecord;
    readonly navigation: BadgeRuleVersionNavigationModel;
    readonly definition: BadgeIssuanceRuleDefinition;
    readonly orgUnit: TenantOrgUnitRecord | null;
    readonly submittedByEmail: string | null;
    readonly impactPreview: BadgeRuleImpactPreview;
    readonly approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
    readonly approvalEvents: readonly BadgeIssuanceRuleApprovalEventRecord[];
    readonly action: BadgeRuleReviewAction;
    readonly listNotice: string | null;
    readonly listError: string | null;
  },
): AppPage => {
  const version = input.navigation.selectedVersion;
  const displayFields = badgeRuleVersionDisplayFields(version);
  const comparison = buildBadgeRuleReviewComparison({
    baseVersion: input.navigation.previousVersion,
    selectedVersion: version,
  });

  return renderBadgeRuleApprovalsShellPage(shell, {
    title: `Review ${displayFields.displayName} · Institution Admin · ${shell.tenant.displayName}`,
    assets: [
      "institutionAdminCss",
      "institutionAdminRuleVersionCss",
      "institutionAdminRuleApprovalReviewCss",
      "institutionAdminShellJs",
      "institutionAdminRuleVersionJs",
      "institutionAdminRuleApprovalReviewJs",
    ],
    children: (
      <>
        <p class="ct-admin__rule-version-back-link">
          <a href={buildBadgeRuleApprovalsPath(shell.tenant.id)}>← Back to approvals</a>
        </p>
        <AdminPageHeader
          title={displayFields.displayName}
          description="Compare the changes, check learner impact, and record your decision."
        />
        <section class="ct-admin ct-stack">
          {input.listError === null ? null : (
            <AdminStatus data-tone="error">{input.listError}</AdminStatus>
          )}
          {input.listNotice === null ? null : (
            <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
          )}
          <BadgeRuleVersionNavigator
            tenantId={shell.tenant.id}
            rule={input.rule}
            navigation={input.navigation}
            destination="approval_review"
          />
          <div class="ct-admin__review-layout">
            <div class="ct-admin__review-primary">
              <BadgeRuleApprovalReviewDiff comparison={comparison} />
              <BadgeRuleApprovalReviewImpact
                tenantId={shell.tenant.id}
                ruleId={input.rule.id}
                versionId={version.id}
                preview={input.impactPreview}
              />
            </div>
            <aside class="ct-admin__review-decision-rail" aria-label="Review decision">
              <BadgeRuleApprovalReviewDecision
                tenantId={shell.tenant.id}
                ruleId={input.rule.id}
                versionId={version.id}
                action={input.action}
              />
            </aside>
            <div class="ct-admin__review-supporting">
              <BadgeRuleVersionOverview
                tenantId={shell.tenant.id}
                rule={input.rule}
                version={version}
                latestVersion={input.navigation.latestVersion}
                definition={input.definition}
                orgUnit={input.orgUnit}
                {...(input.submittedByEmail === null
                  ? {}
                  : { submittedByEmail: input.submittedByEmail })}
              />
              <BadgeRuleApprovalReviewHistory
                steps={input.approvalSteps}
                events={input.approvalEvents}
              />
            </div>
          </div>
        </section>
      </>
    ),
  });
};
