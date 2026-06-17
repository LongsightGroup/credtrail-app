import type { TenantMembershipRole } from "@credtrail/db";
import type { LtiRoleKind } from "@credtrail/lti";

export interface LtiBulkIssuanceRosterMember {
  userId: string;
  sourcedId: string | null;
  displayName: string | null;
  email: string | null;
  roleSummary: string;
  status: string | null;
  issuedAssertionId: string | null;
  issuedAt: string | null;
  issuanceLifecycleState: "active" | "suspended" | "revoked" | "expired" | null;
}

export interface LtiBadgeSummaryCard {
  badgeTemplateId: string;
  title: string;
  summary: string;
  imageUri: string | null;
  criteriaPath: string;
  statusLabel: string;
}

export interface LtiBulkIssuanceView {
  status: "ready" | "unavailable" | "error";
  message: string;
  selectedBadge: LtiBadgeSummaryCard;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string | null;
  learnerCount: number;
  totalCount: number;
  issuanceActionPath: string | null;
  issuanceActionToken: string | null;
  members: readonly LtiBulkIssuanceRosterMember[];
}

export interface LtiCourseBadgeSummaryRow {
  learnerUserId: string;
  learnerName: string;
  learnerEmail: string | null;
  learnerDetailPath: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDetailPath: string | null;
  status: "issued" | "not_issued" | "suspended" | "revoked" | "expired";
  statusLabel: string;
  statusDetail: string;
  assertionId: string | null;
  issuedAt: string | null;
}

export interface LtiCourseBadgeSummaryView {
  status: "ready" | "unavailable" | "error";
  message: string;
  courseContextTitle: string | null;
  learnerCount: number;
  badgeCount: number;
  issuedCount: number;
  canPlaceBadgesFromLti: boolean;
  badges: readonly LtiBadgeSummaryCard[];
  rows: readonly LtiCourseBadgeSummaryRow[];
}

export interface LtiRosterIssuanceResultEntry {
  userId: string;
  displayName: string | null;
  email: string | null;
  status: "issued" | "already_issued" | "skipped" | "failed";
  message: string;
  assertionId: string | null;
}

interface LtiDeepLinkSelectionBaseInput {
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  issuer: string;
  deploymentId: string;
  deepLinkReturnUrl: string;
  targetLinkUri: string;
}

export interface LtiDeepLinkSelectionOption {
  badgeTemplateId: string;
  title: string;
  description: string | null;
  launchUrl: string;
}

export type LtiDeepLinkSelectionPageInput = LtiDeepLinkSelectionBaseInput & {
  mode: "signed";
  signedSelectionActionUrl: string;
  ltiSessionId: string;
  options: readonly LtiDeepLinkSelectionOption[];
};

export type InstructorResourceLinkMode =
  | {
      kind: "bulk";
    }
  | {
      kind: "course-summary";
    };

export interface InstructorResourceLinkViews {
  mode: InstructorResourceLinkMode;
  bulkIssuanceView: LtiBulkIssuanceView | null;
  courseBadgeSummaryView: LtiCourseBadgeSummaryView | null;
}

export type LtiLaunchViewMode =
  | "learner"
  | "bulkReady"
  | "bulkDegraded"
  | "courseSummaryReady"
  | "courseSummaryDegraded"
  | "connected";

export const ltiLaunchViewMode = (input: {
  roleKind: LtiRoleKind;
  instructorViews: InstructorResourceLinkViews | null;
}): LtiLaunchViewMode => {
  if (input.roleKind === "learner") {
    return "learner";
  }

  if (input.instructorViews === null) {
    return "connected";
  }

  if (
    input.instructorViews.mode.kind === "bulk" &&
    input.instructorViews.bulkIssuanceView !== null
  ) {
    return input.instructorViews.bulkIssuanceView.status === "ready" ? "bulkReady" : "bulkDegraded";
  }

  if (
    input.instructorViews.mode.kind === "course-summary" &&
    input.instructorViews.courseBadgeSummaryView !== null
  ) {
    return input.instructorViews.courseBadgeSummaryView.status === "ready"
      ? "courseSummaryReady"
      : "courseSummaryDegraded";
  }

  return "connected";
};
