import type { TenantMembershipRole } from "@credtrail/db";
import type { AppContext } from "../../app/types";
import type { ResolveDatabase } from "../../app/route-deps";
import { loadLearnerRecordReviewLookup } from "../../learner-record/learner-record-review-lookup";
import type { InstitutionAdminLearnerRecordReview } from "../../admin/institution-admin/page-types";
import type { InstitutionAdminPageData } from "../institution-admin-page-data-loader";
import type { TenantGovernanceAdminPageDataLoaders } from "./page-data";

const emptyReview = (
  learner: string | undefined,
  lookupState: Extract<
    InstitutionAdminLearnerRecordReview["lookupState"],
    "idle" | "unresolved" | "ambiguous"
  >,
): InstitutionAdminLearnerRecordReview => ({
  lookup: learner === undefined ? {} : { learner },
  learnerProfile: null,
  presentation: null,
  exportPath: null,
  standardsMappingPath: null,
  lookupState,
});

/** Focused page-data capability for the learner-record review route. */
export interface TenantGovernanceLearnerRecordReviewAdmin {
  readonly loadLearnerRecordReviewPageData: (input: {
    readonly c: AppContext;
    readonly tenantId: string;
    readonly sessionUserId: string;
    readonly membershipRole: TenantMembershipRole;
    readonly learner?: string;
  }) => Promise<InstitutionAdminPageData | Response>;
}

/** Creates the tenant-admin learner-record review page-data loader. */
export const createTenantGovernanceLearnerRecordReviewAdmin = (input: {
  readonly resolveDatabase: ResolveDatabase;
  readonly loadInstitutionAdminPageData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminPageData"];
}): TenantGovernanceLearnerRecordReviewAdmin => {
  const { resolveDatabase, loadInstitutionAdminPageData } = input;

  const loadLearnerRecordReviewPageData = async (reviewInput: {
    readonly c: AppContext;
    readonly tenantId: string;
    readonly sessionUserId: string;
    readonly membershipRole: TenantMembershipRole;
    readonly learner?: string;
  }): Promise<InstitutionAdminPageData | Response> => {
    const pageData = await loadInstitutionAdminPageData(
      reviewInput.c,
      reviewInput.tenantId,
      reviewInput.sessionUserId,
      reviewInput.membershipRole,
    );

    if (pageData instanceof Response) {
      return pageData;
    }

    if (reviewInput.learner === undefined) {
      return { ...pageData, learnerRecordReview: emptyReview(undefined, "idle") };
    }

    const lookup = await loadLearnerRecordReviewLookup(resolveDatabase(reviewInput.c.env), {
      tenantId: reviewInput.tenantId,
      lookupValue: reviewInput.learner,
    });

    if (lookup.status === "not_found") {
      return {
        ...pageData,
        learnerRecordReview: emptyReview(reviewInput.learner, "unresolved"),
      };
    }

    if (lookup.status === "ambiguous") {
      return {
        ...pageData,
        learnerRecordReview: emptyReview(reviewInput.learner, "ambiguous"),
      };
    }

    const encodedTenantId = encodeURIComponent(reviewInput.tenantId);
    const encodedLearnerProfileId = encodeURIComponent(lookup.learnerProfile.id);

    return {
      ...pageData,
      learnerRecordReview: {
        lookup: { learner: reviewInput.learner },
        learnerProfile: {
          id: lookup.learnerProfile.id,
          displayName: lookup.learnerProfile.displayName,
          subjectId: lookup.learnerProfile.subjectId,
        },
        presentation: lookup.presentation,
        exportPath: `/v1/tenants/${encodedTenantId}/learner-records/${encodedLearnerProfileId}/export?profile=native_portable_json`,
        standardsMappingPath: `/v1/tenants/${encodedTenantId}/learner-records/${encodedLearnerProfileId}/standards-mapping?profile=clr_alignment_json`,
        lookupState: "loaded",
      },
    };
  };

  return { loadLearnerRecordReviewPageData };
};
