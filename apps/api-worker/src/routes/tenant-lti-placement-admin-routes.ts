import { retireLtiResourceLinkPlacement } from "@credtrail/db";
import {
  parseLtiResourceLinkPlacementPathParams,
  parseRetireLtiResourceLinkPlacementRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import { buildBadgeRuleVersionDetailPath } from "../admin/access-admin-helpers";
import { setAdminListMessageFlash } from "../admin/admin-list-message-flash";
import type { AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import {
  loadBadgeRuleVersionPageContext,
  type ResolveBadgeRuleVersionPageActor,
} from "./badge-rule-version-page-context";

interface RegisterTenantLtiPlacementAdminRoutesInput {
  readonly app: Hono<AppEnv>;
  readonly resolveDatabase: ResolveDatabase;
  readonly resolveInstitutionAdminAdminRole: ResolveBadgeRuleVersionPageActor;
}

/** Registers the tenant-admin action for retiring one rule-owned LMS placement. */
export const registerTenantLtiPlacementAdminRoutes = (
  input: RegisterTenantLtiPlacementAdminRoutesInput,
): void => {
  input.app.post(
    "/tenants/:tenantId/admin/rules/:ruleId/versions/:versionId/placements/:placementId/retire",
    async (c) => {
      const pathParams = parseLtiResourceLinkPlacementPathParams(c.req.param());
      const nextPath = buildBadgeRuleVersionDetailPath(
        pathParams.tenantId,
        pathParams.ruleId,
        pathParams.versionId,
      );
      const authorized = await loadBadgeRuleVersionPageContext(c, {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        nextPath,
        resolveDatabase: input.resolveDatabase,
        resolveActor: input.resolveInstitutionAdminAdminRole,
      });

      if (authorized instanceof Response) {
        return authorized;
      }

      const formData = await c.req.formData();
      let request: ReturnType<typeof parseRetireLtiResourceLinkPlacementRequest>;

      try {
        request = parseRetireLtiResourceLinkPlacementRequest({
          placementId: formData.get("placementId"),
        });
      } catch {
        await setAdminListMessageFlash(c, {
          tenantId: pathParams.tenantId,
          userId: authorized.principal.userId,
          workspace: "rule_version",
          tone: "error",
          message: "This placement request was invalid. Reload the page and try again.",
        });
        return c.redirect(nextPath, 303);
      }

      if (request.placementId !== pathParams.placementId) {
        await setAdminListMessageFlash(c, {
          tenantId: pathParams.tenantId,
          userId: authorized.principal.userId,
          workspace: "rule_version",
          tone: "error",
          message: "This placement request no longer matches the page. Reload and try again.",
        });
        return c.redirect(nextPath, 303);
      }

      const result = await retireLtiResourceLinkPlacement(input.resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        placementId: pathParams.placementId,
        actorUserId: authorized.principal.userId,
        actorRole: authorized.membershipRole,
      });
      const succeeded = result.status === "retired" || result.status === "already_retired";

      await setAdminListMessageFlash(c, {
        tenantId: pathParams.tenantId,
        userId: authorized.principal.userId,
        workspace: "rule_version",
        tone: succeeded ? "success" : "error",
        message:
          result.status === "retired"
            ? "Placement retired in CredTrail. A verified launch of the LMS link will reactivate it."
            : result.status === "already_retired"
              ? "Placement was already retired in CredTrail."
              : "Placement not found for this rule.",
      });

      return c.redirect(nextPath, 303);
    },
  );
};
