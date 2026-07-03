import { createAuditLog, type CreateAuditLogInput } from "./audit-logs.js";
import { createAssertionIssuanceProvenance } from "./assertion-issuance-provenance.js";
import type {
  AssertionIssuanceProvenanceRecord,
  CreateAssertionIssuanceProvenanceInput,
} from "./assertion-issuance-provenance.js";
import { createAssertion } from "./assertion-writes.js";
import type { AssertionRecord, CreateAssertionInput } from "./assertion-types.js";
import { runSqlTransaction, type SqlDatabase } from "./tenant-scope.js";

export interface FinalizeAssertionIssuanceInput {
  readonly assertion: CreateAssertionInput;
  readonly provenance: Omit<CreateAssertionIssuanceProvenanceInput, "assertionId" | "tenantId">;
  readonly buildAuditLog: (assertion: AssertionRecord) => CreateAuditLogInput;
}

export interface FinalizeAssertionIssuanceResult {
  readonly assertion: AssertionRecord;
  readonly provenance: AssertionIssuanceProvenanceRecord;
}

export const finalizeAssertionIssuance = async (
  db: SqlDatabase,
  input: FinalizeAssertionIssuanceInput,
): Promise<FinalizeAssertionIssuanceResult> => {
  return runSqlTransaction(db, async (transactionDb) => {
    const assertion = await createAssertion(transactionDb, input.assertion);
    await createAuditLog(transactionDb, input.buildAuditLog(assertion));
    const provenance = await createAssertionIssuanceProvenance(transactionDb, {
      ...input.provenance,
      assertionId: assertion.id,
      tenantId: assertion.tenantId,
    });

    return { assertion, provenance };
  });
};
