import { createAuditLog, type CreateAuditLogInput } from "./audit-logs.js";
import { createAssertionIssuanceProvenance } from "./assertion-issuance-provenance.js";
import type {
  AssertionIssuanceProvenanceRecord,
  CreateAssertionIssuanceProvenanceInput,
} from "./assertion-issuance-provenance.js";
import { createAssertion } from "./assertion-writes.js";
import type { AssertionRecord, CreateAssertionInput } from "./assertion-types.js";
import { ensureLearnerLmsIdentity } from "./learner-lms-identities.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

export interface FinalizeAssertionIssuanceInput {
  readonly assertion: CreateAssertionInput;
  readonly provenance: Omit<CreateAssertionIssuanceProvenanceInput, "assertionId" | "tenantId">;
  readonly buildAuditLog: (assertion: AssertionRecord) => CreateAuditLogInput;
  readonly lmsLearnerIdentity?: {
    readonly connectionId: string;
    readonly learnerId: string;
  };
}

/** Atomic assertion-finalization outcome, including an expected LMS identity conflict. */
export type FinalizeAssertionIssuanceResult =
  | {
      readonly status: "issued";
      readonly assertion: AssertionRecord;
      readonly provenance: AssertionIssuanceProvenanceRecord;
    }
  | {
      readonly status: "lms_identity_conflict";
      readonly reason: "lms_learner_id_in_use" | "learner_profile_in_use";
    };

export const finalizeAssertionIssuance = async (
  db: SqlDatabase,
  input: FinalizeAssertionIssuanceInput,
): Promise<FinalizeAssertionIssuanceResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    if (input.lmsLearnerIdentity !== undefined) {
      if (input.assertion.learnerProfileId === undefined) {
        throw new Error("LMS learner identity requires an assertion learner profile");
      }

      const linkResult = await ensureLearnerLmsIdentity(transactionDb, {
        tenantId: input.assertion.tenantId,
        connectionId: input.lmsLearnerIdentity.connectionId,
        lmsLearnerId: input.lmsLearnerIdentity.learnerId,
        learnerProfileId: input.assertion.learnerProfileId,
        linkedAt: input.assertion.issuedAt,
      });

      if (linkResult.status === "conflict") {
        return { status: "lms_identity_conflict", reason: linkResult.reason };
      }
    }

    const assertion = await createAssertion(transactionDb, input.assertion);
    await createAuditLog(transactionDb, input.buildAuditLog(assertion));
    const provenance = await createAssertionIssuanceProvenance(transactionDb, {
      ...input.provenance,
      assertionId: assertion.id,
      tenantId: assertion.tenantId,
    });

    return { status: "issued", assertion, provenance };
  });
};
