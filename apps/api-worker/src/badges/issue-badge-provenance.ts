import type { AssertionIssuanceProvenanceSource } from "@credtrail/db";
import type { IssueBadgeRequest } from "@credtrail/validation";
import type {
  DirectIssueBadgeIssuanceProvenance,
  DirectIssueBadgeRequest,
} from "./recipient-identifiers";

export type RuleBackedIssuanceProvenanceContext = {
  readonly source: Extract<AssertionIssuanceProvenanceSource, "lti_roster" | "rule_evaluate">;
  readonly ruleId: string;
  readonly versionId: string;
  readonly provenanceJson: string;
};

export type IssueBadgeProvenanceContext =
  | RuleBackedIssuanceProvenanceContext
  | { readonly source: Extract<AssertionIssuanceProvenanceSource, "manual"> }
  | { readonly source: Extract<AssertionIssuanceProvenanceSource, "programmatic"> };

export const issuanceProvenanceFromContext = (
  context: IssueBadgeProvenanceContext,
): DirectIssueBadgeIssuanceProvenance => {
  if (context.source === "manual" || context.source === "programmatic") {
    return { source: context.source };
  }

  return {
    source: context.source,
    ruleId: context.ruleId,
    versionId: context.versionId,
    provenanceJson: context.provenanceJson,
  };
};

export const withIssuanceProvenance = <
  TRequest extends Omit<DirectIssueBadgeRequest, "issuanceProvenance">,
>(
  request: TRequest,
  context: IssueBadgeProvenanceContext,
): TRequest & { issuanceProvenance: DirectIssueBadgeIssuanceProvenance } => {
  return {
    ...request,
    issuanceProvenance: issuanceProvenanceFromContext(context),
  };
};

export const manualIssueBadgeProvenance = (): DirectIssueBadgeIssuanceProvenance => {
  return { source: "manual" };
};

export const programmaticIssueBadgeProvenance = (): DirectIssueBadgeIssuanceProvenance => {
  return { source: "programmatic" };
};

export const resolveQueueIssueBadgeProvenance = (
  request: IssueBadgeRequest,
): DirectIssueBadgeIssuanceProvenance => {
  if (request.issuanceProvenance !== undefined) {
    return request.issuanceProvenance;
  }

  return request.requestedByUserId !== undefined
    ? manualIssueBadgeProvenance()
    : programmaticIssueBadgeProvenance();
};
