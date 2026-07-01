import type { LtiServiceError } from "@longsightgroup/lti-tool";
import { isLtiIssuerTenantConflictError } from "@credtrail/db";

export const ltiServiceErrorIndicatesIssuerTenantConflict = (error: LtiServiceError): boolean => {
  let current: unknown = error.cause;

  while (current !== undefined) {
    if (isLtiIssuerTenantConflictError(current)) {
      return true;
    }

    current = current instanceof Error ? current.cause : undefined;
  }

  return false;
};
