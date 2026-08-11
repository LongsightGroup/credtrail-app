import type { TenantMembershipRole } from "@credtrail/db";
import { parseBadgeIssuanceRuleVersionPathParams } from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import type { LoadBadgeRuleVersionReferenceLabels } from "../lms/badge-rule-version-reference-label-service";

interface RegisterBadgeRuleVersionReferenceRoutesInput {
  readonly app: Hono<AppEnv>;
  readonly resolveDatabase: ResolveDatabase;
  readonly requireTenantRole: RequireTenantRole;
  readonly APPROVAL_WORKSPACE_ROLES: readonly TenantMembershipRole[];
  readonly loadReferenceLabels: LoadBadgeRuleVersionReferenceLabels;
}

const statusCodeForFailure = (
  status: "not_found" | "forbidden" | "conflict" | "bad_gateway",
): 403 | 404 | 409 | 502 => {
  switch (status) {
    case "not_found":
      return 404;
    case "forbidden":
      return 403;
    case "conflict":
      return 409;
    case "bad_gateway":
      return 502;
  }
};

/** Registers the read-only label projection for references stored by one governed rule version. */
export const registerBadgeRuleVersionReferenceRoutes = (
  input: RegisterBadgeRuleVersionReferenceRoutesInput,
): void => {
  const { app, resolveDatabase, requireTenantRole, APPROVAL_WORKSPACE_ROLES, loadReferenceLabels } =
    input;

  app.get(
    "/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/lms-reference-labels",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      c.header("Cache-Control", "no-store");
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, APPROVAL_WORKSPACE_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const result = await loadReferenceLabels({
        db: resolveDatabase(c.env),
        ...pathParams,
        actorUserId: roleCheck.session.userId,
        actorRole: roleCheck.membershipRole,
      });

      if (result.status !== "resolved") {
        return c.json({ error: result.error }, statusCodeForFailure(result.status));
      }

      return c.json({
        ...pathParams,
        courses: result.labels.courses,
        assignments: result.labels.assignments,
      });
    },
  );
};
