import type { TenantAssertionSummaryRecord } from "@credtrail/db";
import { IssuedBadgeRows } from "./components";

export const renderIssuedBadgeRowsToString = (
  assertions: readonly TenantAssertionSummaryRecord[],
  auditLifecycleHrefForAssertion: (assertionId: string) => string,
  revokeLifecycleHrefForAssertion: (assertionId: string) => string,
): string => {
  const renderable = (
    <IssuedBadgeRows
      assertions={assertions}
      auditLifecycleHrefForAssertion={auditLifecycleHrefForAssertion}
      revokeLifecycleHrefForAssertion={revokeLifecycleHrefForAssertion}
    />
  ) as { toString(): string };

  return renderable.toString();
};
