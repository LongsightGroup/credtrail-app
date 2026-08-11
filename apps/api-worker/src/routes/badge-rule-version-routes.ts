import {
  activateBadgeIssuanceRuleVersion,
  createAuditLog,
  createBadgeIssuanceRuleVersion,
  decideBadgeIssuanceRuleVersion,
  findBadgeIssuanceRuleById,
  findBadgeIssuanceRuleVersionById,
  listBadgeIssuanceRuleVersionApprovalEvents,
  listBadgeIssuanceRuleVersionApprovalSteps,
  listBadgeIssuanceRuleVersions,
  previousBadgeIssuanceRuleVersion,
  submitBadgeIssuanceRuleVersionForApproval,
  type TenantMembershipRole,
} from "@credtrail/db";
import {
  apiDecideBadgeRuleVersionErrorMessage,
  apiDecideBadgeRuleVersionStatusCode,
  apiSubmitBadgeRuleVersionStatusCode,
  submitBadgeRuleVersionForApprovalFailureMessage,
} from "../badges/badge-rule-approval-outcomes";
import {
  parseBadgeIssuanceRulePathParams,
  parseBadgeIssuanceRuleVersionDiffQuery,
  parseBadgeIssuanceRuleVersionPathParams,
  parseCreateBadgeIssuanceRuleVersionRequest,
  parseDecideBadgeIssuanceRuleVersionRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppEnv } from "../app";
import type { RequireTenantRole, ResolveDatabase } from "../app/route-deps";
import { buildBadgeRuleVersionDefinitionDiff } from "../badges/badge-rule-version-diff";

interface RegisterBadgeRuleVersionRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: ResolveDatabase;
  requireTenantRole: RequireTenantRole;
  ISSUER_ROLES: readonly TenantMembershipRole[];
  ADMIN_ROLES: readonly TenantMembershipRole[];
  TENANT_MEMBER_ROLES: readonly TenantMembershipRole[];
}

export const registerBadgeRuleVersionRoutes = (
  input: RegisterBadgeRuleVersionRoutesInput,
): void => {
  const {
    app,
    resolveDatabase,
    requireTenantRole,
    ISSUER_ROLES,
    ADMIN_ROLES,
    TENANT_MEMBER_ROLES,
  } = input;

  app.get("/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/diff", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    let query;

    try {
      query = parseBadgeIssuanceRuleVersionDiffQuery(c.req.query());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule version diff query",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const db = resolveDatabase(c.env);
    const selectedVersion = await findBadgeIssuanceRuleVersionById(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });

    if (selectedVersion === null) {
      return c.json(
        {
          error: "Badge rule version not found",
        },
        404,
      );
    }

    const versions = await listBadgeIssuanceRuleVersions(db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
    });
    const baseVersion =
      query.baseVersionId === undefined
        ? previousBadgeIssuanceRuleVersion(versions, selectedVersion.versionNumber)
        : (versions.find((candidate) => candidate.id === query.baseVersionId) ?? null);

    if (baseVersion === null) {
      return c.json(
        {
          error:
            query.baseVersionId === undefined
              ? "No base version found. Specify baseVersionId to compare against."
              : "Base badge rule version not found",
        },
        404,
      );
    }

    const diff = buildBadgeRuleVersionDefinitionDiff({
      baseRuleJson: baseVersion.ruleJson,
      selectedRuleJson: selectedVersion.ruleJson,
    });

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      selectedVersion: {
        id: selectedVersion.id,
        versionNumber: selectedVersion.versionNumber,
        status: selectedVersion.status,
      },
      baseVersion: {
        id: baseVersion.id,
        versionNumber: baseVersion.versionNumber,
        status: baseVersion.status,
      },
      diff,
    });
  });

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/versions", async (c) => {
    const pathParams = parseBadgeIssuanceRulePathParams(c.req.param());
    let request;

    try {
      request = parseCreateBadgeIssuanceRuleVersionRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule version payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const existingRule = await findBadgeIssuanceRuleById(
      resolveDatabase(c.env),
      pathParams.tenantId,
      pathParams.ruleId,
    );

    if (existingRule === null) {
      return c.json(
        {
          error: "Badge rule not found",
        },
        404,
      );
    }

    const createdVersion = await createBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      ruleJson: JSON.stringify(request.definition),
      changeSummary: request.changeSummary,
      createdByUserId: session.userId,
    });

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_created",
      targetType: "badge_rule_version",
      targetId: createdVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: createdVersion.versionNumber,
        status: createdVersion.status,
      },
    });

    return c.json(
      {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        version: createdVersion,
      },
      201,
    );
  });

  app.post(
    "/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/submit-approval",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const { session, membershipRole } = roleCheck;
      const db = resolveDatabase(c.env);
      const submitResult = await submitBadgeIssuanceRuleVersionForApproval(db, {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
        actorUserId: session.userId,
        actorRole: membershipRole,
      });

      if (submitResult.status !== "submitted") {
        return c.json(
          {
            error: submitBadgeRuleVersionForApprovalFailureMessage(submitResult),
          },
          apiSubmitBadgeRuleVersionStatusCode(submitResult),
        );
      }

      const updatedVersion = submitResult.version;

      return c.json({
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        version: updatedVersion,
      });
    },
  );

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/decision", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    let request;

    try {
      request = parseDecideBadgeIssuanceRuleVersionRequest(await c.req.json<unknown>());
    } catch {
      return c.json(
        {
          error: "Invalid badge rule approval decision payload",
        },
        400,
      );
    }

    const roleCheck = await requireTenantRole(c, pathParams.tenantId, TENANT_MEMBER_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const decisionResult = await decideBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      decision: request.decision,
      actorUserId: session.userId,
      actorRole: membershipRole,
      comment: request.comment,
    });

    if (decisionResult.status !== "decided") {
      return c.json(
        {
          error: apiDecideBadgeRuleVersionErrorMessage(decisionResult),
        },
        apiDecideBadgeRuleVersionStatusCode(decisionResult),
      );
    }

    const decidedVersion = decisionResult.version;

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      version: decidedVersion,
    });
  });

  app.get(
    "/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/approval-history",
    async (c) => {
      const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
      const roleCheck = await requireTenantRole(c, pathParams.tenantId, ISSUER_ROLES);

      if (roleCheck instanceof Response) {
        return roleCheck;
      }

      const version = await findBadgeIssuanceRuleVersionById(resolveDatabase(c.env), {
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        versionId: pathParams.versionId,
      });

      if (version === null) {
        return c.json(
          {
            error: "Badge rule version not found",
          },
          404,
        );
      }

      const [steps, events] = await Promise.all([
        listBadgeIssuanceRuleVersionApprovalSteps(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
        }),
        listBadgeIssuanceRuleVersionApprovalEvents(resolveDatabase(c.env), {
          tenantId: pathParams.tenantId,
          ruleId: pathParams.ruleId,
          versionId: pathParams.versionId,
        }),
      ]);
      const currentStep = steps.find((step) => step.status === "pending") ?? null;

      return c.json({
        tenantId: pathParams.tenantId,
        ruleId: pathParams.ruleId,
        version,
        approval: {
          currentStep,
          steps,
          events,
        },
      });
    },
  );

  app.post("/v1/tenants/:tenantId/badge-rules/:ruleId/versions/:versionId/activate", async (c) => {
    const pathParams = parseBadgeIssuanceRuleVersionPathParams(c.req.param());
    const roleCheck = await requireTenantRole(c, pathParams.tenantId, ADMIN_ROLES);

    if (roleCheck instanceof Response) {
      return roleCheck;
    }

    const { session, membershipRole } = roleCheck;
    const currentVersion = await findBadgeIssuanceRuleVersionById(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
    });

    if (currentVersion === null) {
      return c.json(
        {
          error: "Badge rule version not found",
        },
        404,
      );
    }

    if (currentVersion.status !== "approved" && currentVersion.status !== "active") {
      return c.json(
        {
          error: `Only approved versions can be activated (current: ${currentVersion.status})`,
        },
        409,
      );
    }

    const activatedVersion = await activateBadgeIssuanceRuleVersion(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      versionId: pathParams.versionId,
      actorUserId: session.userId,
    });

    if (activatedVersion === null) {
      return c.json(
        {
          error: "Badge rule version not found",
        },
        404,
      );
    }

    await createAuditLog(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      actorUserId: session.userId,
      action: "badge_rule.version_activated",
      targetType: "badge_rule_version",
      targetId: activatedVersion.id,
      metadata: {
        role: membershipRole,
        ruleId: pathParams.ruleId,
        versionNumber: activatedVersion.versionNumber,
        status: activatedVersion.status,
      },
    });

    return c.json({
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      version: activatedVersion,
    });
  });
};
