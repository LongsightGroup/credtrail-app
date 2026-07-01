import { badgeTemplateAdminEditorHref } from "../admin/badge-template-admin-helpers";
import { buildInstitutionAdminViewPaths } from "../admin/institution-admin/view-paths";
import {
  emptyIssuedBadgesPageFilterValues,
  issuedBadgesPageUrl,
} from "../admin/issued-badges-admin-helpers";

const LTI_COURSE_SUMMARY_SOURCE = "lti-course-summary";
const LTI_DEEP_LINK_SOURCE = "lti-deep-link";

export const ltiCourseSummaryIssuedBadgesPath = (input: {
  readonly tenantId: string;
  readonly email: string;
  readonly badgeTemplateId?: string;
  readonly assertionId?: string;
}): string => {
  const extra =
    input.assertionId === undefined
      ? { source: LTI_COURSE_SUMMARY_SOURCE }
      : {
          lifecycle: input.assertionId,
          lifecycleMode: "audit",
          source: LTI_COURSE_SUMMARY_SOURCE,
        };

  return issuedBadgesPageUrl(
    input.tenantId,
    {
      ...emptyIssuedBadgesPageFilterValues(),
      recipientQuery: input.email,
      badgeTemplateId: input.badgeTemplateId ?? "",
    },
    extra,
  );
};

export const ltiCourseSummaryBadgeSetupPath = (input: {
  readonly tenantId: string;
  readonly badgeTemplateId: string;
  readonly contextId: string;
  readonly resourceLinkId: string;
  readonly courseContextTitle: string | null;
}): string => {
  const query = new URLSearchParams({
    ltiContextId: input.contextId,
    ltiResourceLinkId: input.resourceLinkId,
    source: LTI_COURSE_SUMMARY_SOURCE,
  });

  if (input.courseContextTitle !== null) {
    query.set("ltiCourse", input.courseContextTitle);
  }

  return `${badgeTemplateAdminEditorHref(input.tenantId, input.badgeTemplateId)}?${query.toString()}`;
};

export const ltiDeepLinkAdvancedSetupPath = (input: {
  readonly requestUrl: string;
  readonly tenantId: string;
  readonly badgeTemplateId: string;
  readonly contextId: string | null;
}): string => {
  const adminPaths = buildInstitutionAdminViewPaths(input.tenantId);
  const advancedSetupUrl = new URL(adminPaths.ruleBuilderPath, input.requestUrl);
  advancedSetupUrl.searchParams.set("badgeTemplateId", input.badgeTemplateId);
  advancedSetupUrl.searchParams.set("source", LTI_DEEP_LINK_SOURCE);

  const normalizedContextId = input.contextId?.trim() ?? "";
  if (normalizedContextId.length > 0) {
    advancedSetupUrl.searchParams.set("ltiContextId", normalizedContextId);
  }

  return `${advancedSetupUrl.pathname}${advancedSetupUrl.search}`;
};
