import type { listLtiIssuerRegistrations, SqlDatabase } from "@credtrail/db";
import type { AppBindings, AppContext } from "../app/types";
import {
  ltiIssuerRegistryFromStoredRows,
  parseLtiIssuerRegistryFromEnv,
  type LtiIssuerRegistry,
} from "./lti-helpers";

export const createResolveLtiIssuerRegistry = (input: {
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  listLtiIssuerRegistrations: typeof listLtiIssuerRegistrations;
}) => {
  return async (c: AppContext): Promise<LtiIssuerRegistry> => {
    const envRegistry = parseLtiIssuerRegistryFromEnv(c.env.LTI_ISSUER_REGISTRY_JSON);
    const dbRows = await input.listLtiIssuerRegistrations(input.resolveDatabase(c.env));
    const dbRegistry = ltiIssuerRegistryFromStoredRows(dbRows);
    return {
      ...envRegistry,
      ...dbRegistry,
    };
  };
};
