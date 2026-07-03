import type { AssertionIssuanceProvenanceSource } from "@credtrail/db";
import type { AssertionEvidenceLoadedData } from "./assertion-evidence-payload";

/**
 * Infers issuance source for assertions created before immutable provenance records existed.
 * New issuances must always write `assertion_issuance_provenance` and should not rely on this.
 */
export const inferLegacyIssuanceSource = (
  data: AssertionEvidenceLoadedData,
): AssertionIssuanceProvenanceSource => {
  if (data.evaluation !== null) {
    return "rule_evaluate";
  }

  if (data.assertion.issuedByUserId !== null) {
    return "manual";
  }

  if (data.assertion.idempotencyKey.startsWith("rule:")) {
    return "rule_evaluate";
  }

  return "programmatic";
};
