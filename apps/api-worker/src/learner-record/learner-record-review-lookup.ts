import {
  listLearnerProfilesForRecordLookup,
  type LearnerProfileRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { loadLearnerRecordExportBundle } from "./learner-record-export";
import {
  createLearnerRecordPresentation,
  type LearnerRecordPresentationModel,
} from "./learner-record-presentation";

/** Canonical result of resolving a tenant administrator's learner-record lookup. */
export type LearnerRecordReviewLookupResult =
  | { readonly status: "not_found" }
  | { readonly status: "ambiguous" }
  | {
      readonly status: "found";
      readonly learnerProfile: LearnerProfileRecord;
      readonly presentation: LearnerRecordPresentationModel;
    };

/** Resolves one administrator-supplied LMS learner ID or email into a reviewable record. */
export const loadLearnerRecordReviewLookup = async (
  db: SqlDatabase,
  input: {
    readonly tenantId: string;
    readonly lookupValue: string;
  },
): Promise<LearnerRecordReviewLookupResult> => {
  const profiles = await listLearnerProfilesForRecordLookup(db, input);

  if (profiles.length === 0) {
    return { status: "not_found" };
  }

  if (profiles.length > 1) {
    return { status: "ambiguous" };
  }

  const learnerProfile = profiles[0];

  if (learnerProfile === undefined) {
    throw new Error("Single learner lookup result was unexpectedly absent");
  }

  const bundle = await loadLearnerRecordExportBundle(db, {
    tenantId: input.tenantId,
    learnerProfileId: learnerProfile.id,
  });

  if (bundle === null) {
    return { status: "not_found" };
  }

  return {
    status: "found",
    learnerProfile,
    presentation: createLearnerRecordPresentation(bundle),
  };
};
