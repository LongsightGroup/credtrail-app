import type { SessionRecord, TenantMembershipRole } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";

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
        session: SessionRecord;
        membershipRole: TenantMembershipRole;
      }
  >;
}
