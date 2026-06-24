import type { ObservabilityContext } from "@credtrail/core-domain";
import type { AppBindings } from "./types";

export const API_SERVICE_NAME = "api-worker";

export const observabilityContext = (bindings: AppBindings): ObservabilityContext => {
  return {
    service: API_SERVICE_NAME,
    environment: bindings.APP_ENV,
  };
};
