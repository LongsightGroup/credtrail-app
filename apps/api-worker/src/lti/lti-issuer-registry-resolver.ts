import type { listAllLtiIssuerRegistrations } from "@credtrail/db";
import type { AppContext } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import {
  ltiIssuerRegistryFromStoredRows,
  parseLtiIssuerRegistryFromEnv,
} from "./lti-issuer-registry-config";
import type { LtiIssuerRegistry } from "./lti-issuer-registry";

export const createResolveLtiIssuerRegistry = (input: {
  resolveDatabase: ResolveDatabase;
  listAllLtiIssuerRegistrations: typeof listAllLtiIssuerRegistrations;
}) => {
  return async (c: AppContext): Promise<LtiIssuerRegistry> => {
    const envRegistry = parseLtiIssuerRegistryFromEnv(c.env.LTI_ISSUER_REGISTRY_JSON);
    const dbRows = await input.listAllLtiIssuerRegistrations(input.resolveDatabase(c.env));
    const dbRegistry = ltiIssuerRegistryFromStoredRows(dbRows);
    return {
      ...envRegistry,
      ...dbRegistry,
    };
  };
};
