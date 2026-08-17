import type { TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import type { AuthenticatedPrincipal } from "../auth/auth-context";

export interface TenantAccessAdminRouteDeps {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        principal: AuthenticatedPrincipal;
        membershipRole: TenantMembershipRole;
      }
  >;
}
