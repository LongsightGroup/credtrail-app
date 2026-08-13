import type { JsonObject } from "@credtrail/core-domain";
import type {
  AssertionRecord,
  BadgeIssuanceRuleApprovalEventRecord,
  BadgeIssuanceRuleApprovalStepRecord,
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateOwnershipEventRecord,
  BadgeTemplateRecord,
  PublicBadgeWallEntryRecord,
  ResolveAssertionLifecycleStateResult,
  TenantOrgUnitRecord,
} from "@credtrail/db";
import type { AppPage } from "../ui/render-page";
import type { PublicBadgeViewModel } from "./public-badge-model";
import type {
  AchievementDetails,
  EvidenceDetails,
  TrustEdCredentialDetails,
} from "./public-badge-helpers";

export interface CreatePublicBadgePageRenderersInput {
  asString: (value: unknown) => string | null;
  achievementDetailsFromCredential: (credential: JsonObject) => AchievementDetails;
  badgeNameFromCredential: (credential: JsonObject) => string;
  evidenceDetailsFromCredential: (credential: JsonObject) => EvidenceDetails[];
  formatIsoTimestamp: (timestampIso: string) => string;
  githubAvatarUrlForUsername: (username: string) => string;
  githubUsernameFromUrl: (value: string) => string | null;
  imsOb3ValidatorUrl: (targetUrl: string) => string;
  isWebUrl: (value: string) => boolean;
  issuerIdentifierFromCredential: (credential: JsonObject) => string | null;
  issuerNameFromCredential: (credential: JsonObject) => string;
  issuerUrlFromCredential: (credential: JsonObject) => string | null;
  linkedInAddToProfileUrl: (input: {
    badgeName: string;
    issuerName: string;
    issuedAtIso: string;
    credentialUrl: string;
    credentialId: string;
  }) => string;
  publicBadgePathForAssertion: (assertion: AssertionRecord) => string;
  recipientAvatarUrlFromAssertion: (assertion: AssertionRecord) => string | null;
  recipientDisplayNameFromAssertion: (assertion: AssertionRecord) => string | null;
  recipientFromCredential: (credential: JsonObject) => string;
  trustEdCredentialDetailsFromCredential: (credential: JsonObject) => TrustEdCredentialDetails;
}

export interface PublicBadgePageRenderers {
  publicBadgeNotFoundPage: (requestUrl: string) => AppPage;
  publicBadgePage: (requestUrl: string, model: PublicBadgeViewModel) => AppPage;
  tenantBadgeWallPage: (
    requestUrl: string,
    tenantId: string,
    entries: readonly PublicBadgeWallEntryViewRecord[],
    filterBadgeTemplateId: string | null,
  ) => AppPage;
  tenantBadgeCriteriaRegistryPage: (
    requestUrl: string,
    tenantId: string,
    model: PublicBadgeCriteriaRegistryViewModel,
    filterBadgeTemplateId: string | null,
  ) => AppPage;
}

export interface PublicBadgeWallEntryViewRecord extends PublicBadgeWallEntryRecord {
  lifecycle: ResolveAssertionLifecycleStateResult;
}

export interface PublicBadgeCriteriaRuleViewRecord {
  rule: BadgeIssuanceRuleRecord;
  latestVersion: BadgeIssuanceRuleVersionRecord | null;
  activeVersion: BadgeIssuanceRuleVersionRecord | null;
  approvalSteps: readonly BadgeIssuanceRuleApprovalStepRecord[];
  approvalEvents: readonly BadgeIssuanceRuleApprovalEventRecord[];
}

export interface PublicBadgeCriteriaTemplateViewRecord {
  template: BadgeTemplateRecord;
  ownerOrgUnit: TenantOrgUnitRecord | null;
  ownershipEvents: readonly BadgeTemplateOwnershipEventRecord[];
  rules: readonly PublicBadgeCriteriaRuleViewRecord[];
}

export interface PublicBadgeCriteriaRegistryViewModel {
  orgUnits: readonly TenantOrgUnitRecord[];
  templates: readonly PublicBadgeCriteriaTemplateViewRecord[];
}
