import type { TenantMembershipRole } from "@credtrail/db";
import type { LtiRosterIssuanceBehaviorKey } from "./issuance-behavior";
import type { LtiRosterEligibilityStatus } from "./roster-eligibility";

export type LtiRoleKind = "instructor" | "learner" | "unknown";

export interface LtiBulkIssuanceRosterMember {
  userId: string;
  lisPersonSourcedId?: string;
  displayName: string;
  email: string | null;
  roleSummary: string;
  status: string | null;
  eligibilityStatus: LtiRosterEligibilityStatus;
  eligibilityLabel: string;
  eligibilityDetail: string;
  eligibleForIssuance: boolean;
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
}

export interface LtiBadgeSummaryStatus {
  label: string;
  modifier: "active" | "issued" | "not_issued";
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
  issuanceBehaviorKey: LtiRosterIssuanceBehaviorKey;
  issuanceBehaviorLabel: string;
  issuanceBehaviorDetail: string;
  manualIssuanceAllowed: boolean;
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

export type LtiLearnerBadgeClaimState = "claimable" | "claimed" | "accepted";

export interface LtiLearnerBadgeSummaryItem {
  badge: LtiBadgeSummaryCard;
  status: LtiBadgeSummaryStatus;
  issuedAt: string | null;
  claimState: LtiLearnerBadgeClaimState | null;
  claimActionPath: string | null;
  sharePath: string | null;
}

export interface LtiLearnerBadgeSummaryView {
  scope: "course" | "selected";
  status: "ready" | "unavailable" | "error";
  message: string;
  badges: readonly LtiLearnerBadgeSummaryItem[];
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
  advancedSetupUrl: string;
}

export type LtiDeepLinkSelectionPageInput = LtiDeepLinkSelectionBaseInput & {
  mode: "signed";
  signedSelectionActionUrl: string;
  ltiSessionId: string;
  options: readonly LtiDeepLinkSelectionOption[];
};

export type InstructorResourceLinkViews =
  | {
      kind: "bulk";
      bulkIssuanceView: LtiBulkIssuanceView;
      courseBadgeSummaryView: null;
    }
  | {
      kind: "course-summary";
      bulkIssuanceView: null;
      courseBadgeSummaryView: LtiCourseBadgeSummaryView;
    };

export type LtiLaunchViewMode =
  | "learner"
  | "learnerDegraded"
  | "bulkReady"
  | "bulkDegraded"
  | "courseSummaryReady"
  | "courseSummaryDegraded"
  | "connected";

export const ltiLaunchViewMode = (input: {
  roleKind: LtiRoleKind;
  instructorViews: InstructorResourceLinkViews | null;
  learnerView: LtiLearnerBadgeSummaryView | null;
}): LtiLaunchViewMode => {
  if (input.roleKind === "learner") {
    return input.learnerView?.status === "ready" ? "learner" : "learnerDegraded";
  }

  if (input.instructorViews === null) {
    return "connected";
  }

  if (input.instructorViews.kind === "bulk") {
    return input.instructorViews.bulkIssuanceView.status === "ready" ? "bulkReady" : "bulkDegraded";
  }

  if (input.instructorViews.kind === "course-summary") {
    return input.instructorViews.courseBadgeSummaryView.status === "ready"
      ? "courseSummaryReady"
      : "courseSummaryDegraded";
  }

  return "connected";
};
