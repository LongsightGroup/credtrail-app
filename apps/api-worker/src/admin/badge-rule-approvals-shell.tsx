import type {
  BadgeIssuanceRuleApprovalStepRecord,
  TenantMembershipRole,
  TenantRecord,
} from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import type { AppPage } from "../ui/render-page";
import type { PageAssetKey } from "../ui/page-assets";
import { renderInstitutionAdminShellPage } from "./institution-admin-shell";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

/** Shared institution-admin shell context for badge-rule approval pages. */
export interface BadgeRuleApprovalsShellInput {
  readonly tenant: TenantRecord;
  readonly userId: string;
  readonly userEmail?: string | undefined;
  readonly membershipRole: TenantMembershipRole;
  readonly switchOrganizationPath?: string | null | undefined;
}

/** Formats the reviewer target represented by one approval step. */
export const badgeRuleApprovalStepTargetLabel = (
  step: BadgeIssuanceRuleApprovalStepRecord,
): string => {
  if (step.targetType === "user") {
    return "Named approver";
  }

  if (step.targetType === "approver_group") {
    return step.requiredRole === null ? "Approver group" : `Approver group · ${step.requiredRole}+`;
  }

  return `${step.requiredRole}+`;
};

/** Renders approval-workspace content inside the institution-admin shell. */
export const renderBadgeRuleApprovalsShellPage = (
  shell: BadgeRuleApprovalsShellInput,
  input: {
    readonly title: string;
    readonly children: HonoElement;
    readonly assets: readonly PageAssetKey[];
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
    assets: [...input.assets],
    contextJson: {},
    children: input.children,
  });
};
