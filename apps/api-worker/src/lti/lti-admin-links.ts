import { badgeTemplateAdminEditorHref } from "../admin/badge-template-admin-helpers";
import {
  emptyIssuedBadgesPageFilterValues,
  issuedBadgesPageUrl,
} from "../admin/issued-badges-admin-helpers";

const LTI_COURSE_SUMMARY_SOURCE = "lti-course-summary";

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

export const ltiCourseSummaryBadgeDetailsPath = (input: {
  readonly tenantId: string;
  readonly badgeTemplateId: string;
}): string => {
  return badgeTemplateAdminEditorHref(input.tenantId, input.badgeTemplateId);
};
