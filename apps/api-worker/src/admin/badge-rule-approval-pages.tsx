import type { PendingBadgeIssuanceRuleApprovalRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { buildBadgeRuleVersionReviewPath } from "./access-admin-helpers";
import {
  badgeRuleApprovalStepTargetLabel,
  renderBadgeRuleApprovalsShellPage,
  type BadgeRuleApprovalsShellInput,
} from "./badge-rule-approvals-shell";
import {
  AdminButtonLink,
  AdminEmptyTableRow,
  AdminMeta,
  AdminPageHeader,
  AdminPanel,
  AdminStatus,
  AdminTable,
} from "./components";
import { formatIsoTimestamp } from "../utils/display-format";
import type { AppPage } from "../ui/render-page";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const formatSubmittedAt = (submittedAt: string | null): string => {
  return submittedAt === null ? "Not recorded" : formatIsoTimestamp(submittedAt);
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
              {entry.versionName}
            </a>
            <AdminMeta>
              Version {String(entry.versionNumber)} · {entry.badgeTemplateTitle}
            </AdminMeta>
          </th>
          <td>{entry.orgUnitDisplayName ?? entry.orgUnitId}</td>
          <td>{entry.currentStep.label ?? `Step ${String(entry.currentStep.stepNumber)}`}</td>
          <td>{badgeRuleApprovalStepTargetLabel(entry.currentStep)}</td>
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

/** Renders the badge-rule versions awaiting the current reviewer's decision. */
export const badgeRuleApprovalsQueuePage = (
  shell: BadgeRuleApprovalsShellInput,
  input: {
    readonly entries: readonly PendingBadgeIssuanceRuleApprovalRecord[];
    readonly listNotice: string | null;
    readonly listError: string | null;
  },
): AppPage => {
  return renderBadgeRuleApprovalsShellPage(shell, {
    title: `Approvals · Institution Admin · ${shell.tenant.displayName}`,
    assets: ["institutionAdminCss", "institutionAdminShellJs"],
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
