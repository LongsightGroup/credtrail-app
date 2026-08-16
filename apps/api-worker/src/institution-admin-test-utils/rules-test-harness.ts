import { beforeEach } from "vitest";
import { resetInstitutionAdminTestDefaults } from "./reset-defaults";

beforeEach(resetInstitutionAdminTestDefaults);

export {
  createEnv,
  fakeDb,
  mockedCountBadgeTemplateImageRevisions,
  mockedCreateAuditLogDb,
  mockedCreateBadgeIssuanceRuleValueList,
  mockedCreateBadgeTemplate,
  mockedDecideBadgeIssuanceRuleVersionDb,
  mockedDeleteBadgeIssuanceRuleBuilderDraftByIdDb,
  mockedDeleteNeverActiveBadgeIssuanceRuleDb,
  mockedFindBadgeIssuanceRuleBuilderDraftDb,
  mockedFindBadgeIssuanceRuleById,
  mockedFindBadgeIssuanceRuleEvaluationById,
  mockedFindBadgeIssuanceRuleVersionByIdDb,
  mockedFindBadgeTemplateById,
  mockedFindBadgeTemplateImageRevisionById,
  mockedFindTenantById,
  mockedFindTenantMembership,
  mockedFindTenantOrgUnitById,
  mockedFindUserById,
  mockedListBadgeIssuanceRuleBuilderDraftsForUserDb,
  mockedListBadgeIssuanceRuleEvaluations,
  mockedListBadgeIssuanceRuleRegistryPageDb,
  mockedListBadgeIssuanceRules,
  mockedListBadgeIssuanceRuleValueLists,
  mockedListBadgeIssuanceRuleVersionApprovalStepsDb,
  mockedListBadgeIssuanceRuleVersions,
  mockedListBadgeIssuanceRuleVersionsForRules,
  mockedListBadgeTemplateImageRevisionCountsByTenant,
  mockedListBadgeTemplateImageRevisions,
  mockedListBadgeTemplates,
  mockedReopenApprovedBadgeIssuanceRuleVersionDb,
  mockedResolveBadgeIssuanceRuleEvaluationReview,
  mockedSetBadgeTemplateArchivedState,
  mockedSubmitBadgeIssuanceRuleVersionForApprovalDb,
  mockedUpdateBadgeTemplate,
  mockedWithdrawBadgeIssuanceRuleVersionSubmissionDb,
  sampleMembership,
} from "./support";
export {
  mockedEnqueueJobQueueMessageOnce,
  mockedFindLtiResourceLinkPlacementForRule,
  mockedListAccessibleTenantContextsForUser,
  mockedListBadgeIssuanceRuleVersionApprovalEvents,
  mockedListPendingBadgeIssuanceRuleApprovalsForActor,
} from "./register-mocks";
export {
  sampleDetailRule,
  sampleDetailVersion,
  sampleRuleBadgeTemplate,
} from "./rule-version-fixtures";
