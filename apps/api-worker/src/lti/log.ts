import type { ObservabilityFields } from "@credtrail/core-domain";
import type { AppLogger } from "../app/observability";

export const logLtiWarning = (
  logger: AppLogger | undefined,
  message: string,
  context: ObservabilityFields,
): void => {
  logger?.warn(message, {
    component: "lti",
    ...context,
  });
};
