import type {
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  PendingBadgeIssuanceRuleApprovalRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  buildBadgeRuleApprovalsPath,
  buildBadgeRuleVersionImpactPreviewPath,
  buildBadgeRuleVersionReviewDecisionPath,
  buildBadgeRuleVersionReviewPath,
  buildBadgeRuleVersionReviewReopenPath,
} from "./access-admin-helpers";
import {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminField,
  AdminForm,
  AdminMeta,
  AdminPageHeader,
  AdminPanel,
  AdminStatus,
  AdminStatusPill,
  AdminTable,
} from "./components";
import { renderInstitutionAdminShellPage } from "./institution-admin-shell";
import type { AppPage } from "../ui/render-page";
import { CtTextarea } from "../ui/forms";
import { createRuleDefinitionSummaryMarkup } from "../badges/public-badge-rule-summary";
import type { BadgeRuleImpactPreview } from "../lti/badge-rule-impact-preview";
import type { BadgeRuleVersionDefinitionDiff } from "../badges/badge-rule-version-diff";
import { describeRuleDefinitionDiffDetails } from "../badges/badge-rule-version-diff";
import { formatIsoTimestamp } from "../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export interface BadgeRuleApprovalsShellInput {
  readonly tenant: TenantRecord;
  readonly userId: string;
  readonly userEmail?: string | undefined;
  readonly membershipRole: TenantMembershipRole;
  readonly switchOrganizationPath?: string | null | undefined;
}

const formatSubmittedAt = (submittedAt: string | null): string => {
  return submittedAt === null ? "Not recorded" : formatIsoTimestamp(submittedAt);
};

const renderApprovalsShellPage = (
  shell: BadgeRuleApprovalsShellInput,
  input: {
    readonly title: string;
    readonly children: HonoElement;
  },
): AppPage => {
  return renderInstitutionAdminShellPage({
    tenant: shell.tenant,
    userId: shell.userId,
    ...(shell.userEmail === undefined ? {} : { userEmail: shell.userEmail }),
    membershipRole: shell.membershipRole,
    ...(shell.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: shell.switchOrganizationPath }),
    view: "rulesApprovals",
    title: input.title,
    assets: ["institutionAdminCss", "institutionAdminShellJs"],
    contextJson: {},
    children: input.children,
  });
};

const approvalStepTargetLabel = (step: BadgeIssuanceRuleApprovalStepRecord): string => {
  if (step.targetType === "user") {
    return "Named approver";
  }

  if (step.targetType === "approver_group") {
    return step.requiredRole === null ? "Approver group" : `Approver group · ${step.requiredRole}+`;
  }

  return `${step.requiredRole}+`;
};

const renderApprovalsRows = (
  tenantId: string,
  entries: readonly PendingBadgeIssuanceRuleApprovalRecord[],
): HonoElement => {
  if (entries.length === 0) {
    return (
      <AdminEmptyTableRow colSpan={6}>
        No badge rule versions are awaiting your decision.
      </AdminEmptyTableRow>
    );
  }

  return (
    <>
      {entries.map((entry) => (
        <tr>
          <th scope="row">
            <a href={buildBadgeRuleVersionReviewPath(tenantId, entry.ruleId, entry.versionId)}>
              {entry.ruleName}
            </a>
            <AdminMeta>
              Version {String(entry.versionNumber)} ·{" "}
              {entry.badgeTemplateName ?? entry.badgeTemplateId}
            </AdminMeta>
          </th>
          <td>{entry.orgUnitDisplayName ?? entry.orgUnitId}</td>
          <td>{entry.currentStep.label ?? `Step ${String(entry.currentStep.stepNumber)}`}</td>
          <td>{approvalStepTargetLabel(entry.currentStep)}</td>
          <td>
            {formatSubmittedAt(entry.submittedAt)}
            <AdminMeta>
              {entry.submittedByEmail ?? entry.submittedByUserId ?? "Submitter not recorded"}
            </AdminMeta>
          </td>
          <td>
            <AdminButtonLink
              href={buildBadgeRuleVersionReviewPath(tenantId, entry.ruleId, entry.versionId)}
              size="tiny"
            >
              Review
            </AdminButtonLink>
          </td>
        </tr>
      ))}
    </>
  );
};

export const badgeRuleApprovalsQueuePage = (
  shell: BadgeRuleApprovalsShellInput,
  input: {
    readonly entries: readonly PendingBadgeIssuanceRuleApprovalRecord[];
    readonly listNotice: string | null;
    readonly listError: string | null;
  },
): AppPage => {
  return renderApprovalsShellPage(shell, {
    title: `Approvals · Institution Admin · ${shell.tenant.displayName}`,
    children: (
      <>
        <AdminPageHeader
          title="Approvals"
          description={`${String(input.entries.length)} badge rule version${
            input.entries.length === 1 ? "" : "s"
          } awaiting your decision.`}
        />
        <section class="ct-admin ct-stack">
          {input.listError === null ? null : (
            <AdminStatus data-tone="error">{input.listError}</AdminStatus>
          )}
          {input.listNotice === null ? null : (
            <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
          )}
          <AdminPanel variant="table">
            <h2>Pending Rule Approvals</h2>
            <AdminTable headers={["Rule", "Scope", "Step", "Target", "Submitted", "Actions"]}>
              {renderApprovalsRows(shell.tenant.id, input.entries)}
            </AdminTable>
          </AdminPanel>
        </section>
      </>
    ),
  });
};

const renderImpactPreview = (input: {
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
      <AdminPanel>
        <h2>Impact Preview</h2>
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

  const { preview } = input;

  if (preview.status === "unavailable") {
    return (
      <AdminPanel>
        <h2>Impact Preview</h2>
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
    <AdminPanel>
      <h2>Impact Preview</h2>
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

const renderDiffPanel = (
  diff: BadgeRuleVersionDefinitionDiff | null,
  baseVersion: BadgeIssuanceRuleVersionRecord | null,
): HonoElement => {
  if (diff === null || baseVersion === null) {
    return (
      <AdminPanel>
        <h2>What Changed</h2>
        <p>No earlier version is available for comparison.</p>
      </AdminPanel>
    );
  }

  return (
    <AdminPanel>
      <h2>What Changed</h2>
      <AdminMeta>Compared with version {String(baseVersion.versionNumber)}</AdminMeta>
      <ul>
        {describeRuleDefinitionDiffDetails(diff).map((description) => (
          <li
            class={
              description.reviewImpact === "loosening"
                ? "ct-admin__review-impact ct-admin__review-impact--loosening"
                : undefined
            }
          >
            {description.reviewImpact === "loosening" ? <strong>Loosening: </strong> : null}
            {description.text}
          </li>
        ))}
      </ul>
    </AdminPanel>
  );
};

const renderApprovalHistory = (input: {
  readonly steps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  readonly events: readonly BadgeIssuanceRuleApprovalEventRecord[];
}): HonoElement => {
  return (
    <AdminPanel>
      <h2>Approval Chain</h2>
      <ol>
        {input.steps.map((step) => (
          <li>
            <strong>{step.label ?? `Step ${String(step.stepNumber)}`}</strong>{" "}
            <AdminStatusPill tone={step.status}>{step.status.replaceAll("_", " ")}</AdminStatusPill>
            <AdminMeta>
              {approvalStepTargetLabel(step)}
              {step.decidedAt === null ? "" : ` · Decided ${formatIsoTimestamp(step.decidedAt)}`}
            </AdminMeta>
            {step.decisionComment === null ? null : <p>{step.decisionComment}</p>}
          </li>
        ))}
      </ol>
      {input.events.length === 0 ? null : (
        <>
          <h3>Events</h3>
          <ul>
            {input.events.map((event) => (
              <li>
                {event.action.replaceAll("_", " ")} · {formatIsoTimestamp(event.occurredAt)}
                <AdminMeta>{event.actorUserId ?? "System"}</AdminMeta>
                {event.comment === null ? null : <p>{event.comment}</p>}
              </li>
            ))}
          </ul>
        </>
      )}
    </AdminPanel>
  );
};

const renderDecisionPanel = (input: {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly canDecide: boolean;
  readonly canReopen: boolean;
}): HonoElement => {
  const action = buildBadgeRuleVersionReviewDecisionPath(
    input.tenantId,
    input.ruleId,
    input.versionId,
  );

  if (input.canReopen) {
    return (
      <AdminPanel>
        <h2>Correct This Approval</h2>
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

  if (!input.canDecide) {
    return (
      <AdminPanel>
        <h2>Decision</h2>
        <p>No approval action is available for this version.</p>
      </AdminPanel>
    );
  }

  return (
    <AdminPanel>
      <h2>Decision</h2>
      <AdminForm method="post" action={action}>
        <AdminField label="Reviewer comment">
          <CtTextarea
            name="comment"
            rows={4}
            variant="prose"
            placeholder="Add context for the author or next reviewer."
          />
        </AdminField>
        <AdminActions>
          <AdminButton type="submit" name="decision" value="approved" variant="primary">
            Approve
          </AdminButton>
          <AdminButton type="submit" name="decision" value="changes_requested" variant="secondary">
            Request changes
          </AdminButton>
          <AdminButton type="submit" name="decision" value="rejected" variant="danger">
            Reject
          </AdminButton>
        </AdminActions>
      </AdminForm>
    </AdminPanel>
  );
};

export const badgeRuleApprovalReviewPage = (
  shell: BadgeRuleApprovalsShellInput,
  input: {
    readonly rule: BadgeIssuanceRuleRecord;
    readonly version: BadgeIssuanceRuleVersionRecord;
    readonly baseVersion: BadgeIssuanceRuleVersionRecord | null;
    readonly diff: BadgeRuleVersionDefinitionDiff | null;
    readonly impactPreview: BadgeRuleImpactPreview;
    readonly approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
    readonly approvalEvents: readonly BadgeIssuanceRuleApprovalEventRecord[];
    readonly canDecide: boolean;
    readonly canReopen: boolean;
    readonly listNotice: string | null;
    readonly listError: string | null;
  },
): AppPage => {
  const courseNamesById =
    input.impactPreview.status === "ready" &&
    input.impactPreview.courseContextId !== null &&
    input.impactPreview.courseTitle !== null
      ? new Map([[input.impactPreview.courseContextId, input.impactPreview.courseTitle]])
      : undefined;
  const ruleSummaryMarkup = createRuleDefinitionSummaryMarkup(formatIsoTimestamp, {
    courseNamesById,
  });

  return renderApprovalsShellPage(shell, {
    title: `Review ${input.rule.name} · Institution Admin · ${shell.tenant.displayName}`,
    children: (
      <>
        <AdminPageHeader
          title={input.rule.name}
          description={`Review version ${String(input.version.versionNumber)} before activation.`}
        />
        <section class="ct-admin ct-stack">
          {input.listError === null ? null : (
            <AdminStatus data-tone="error">{input.listError}</AdminStatus>
          )}
          {input.listNotice === null ? null : (
            <AdminStatus data-tone="success">{input.listNotice}</AdminStatus>
          )}
          <AdminPanel>
            <h2>What This Rule Says</h2>
            {ruleSummaryMarkup(input.version.ruleJson)}
          </AdminPanel>
          {renderDiffPanel(input.diff, input.baseVersion)}
          {renderImpactPreview({
            tenantId: shell.tenant.id,
            ruleId: input.rule.id,
            versionId: input.version.id,
            preview: input.impactPreview,
          })}
          {renderApprovalHistory({
            steps: input.approvalSteps,
            events: input.approvalEvents,
          })}
          {renderDecisionPanel({
            tenantId: shell.tenant.id,
            ruleId: input.rule.id,
            versionId: input.version.id,
            canDecide: input.canDecide,
            canReopen: input.canReopen,
          })}
          <AdminActions>
            <AdminButtonLink href={buildBadgeRuleApprovalsPath(shell.tenant.id)}>
              Back to approvals
            </AdminButtonLink>
          </AdminActions>
        </section>
      </>
    ),
  });
};
